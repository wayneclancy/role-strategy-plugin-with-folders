package com.michelin.cio.hudson.plugins.rolestrategy.folder;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.michelin.cio.hudson.plugins.rolestrategy.Role;
import com.michelin.cio.hudson.plugins.rolestrategy.RoleBasedAuthorizationStrategy;
import com.michelin.cio.hudson.plugins.rolestrategy.RoleMap;
import com.synopsys.arc.jenkins.plugins.rolestrategy.RoleType;
import hudson.Extension;
import hudson.model.Action;
import hudson.model.User;
import hudson.security.Permission;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.verb.POST;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.Nonnull;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Provides a folder-specific permissions management page that integrates
 * with the role-strategy-plugin to allow fine-grained permission control
 * at the folder level.
 */
public class FolderPermissionsAction implements Action {

    private final Folder folder;

    public FolderPermissionsAction(Folder folder) {
        this.folder = folder;
    }

    @Override
    public String getIconFileName() {
        try {
            // Show icon if user can manage folder permissions
            return canManageFolderPermissions() ? "secure.png" : null;
        } catch (Exception e) {
            System.err.println("Error in getIconFileName: " + e.getMessage());
            return null;
        }
    }

    @Override
    public String getDisplayName() {
        return "Folder Permissions";
    }

    @Override
    public String getUrlName() {
        return "folder-permissions";
    }

    /**
     * Gets the folder instance this action is attached to
     */
    public Folder getFolder() {
        return folder;
    }

    /**
     * Gets the full name/path of the folder for pattern matching
     */
    public String getFolderPath() {
        return folder.getFullName();
    }

    /**
     * Simple test method to verify the action is working
     */
    public String doTest() {
        return "Folder Permissions Action is working! Folder: " + folder.getFullName();
    }

    /**
     * Returns all roles that apply to this specific folder
     */
    public Map<Role, Set<String>> getApplicableRoles() {
        Map<Role, Set<String>> applicableRoles = new HashMap<>();

        try {
            RoleBasedAuthorizationStrategy strategy = getRoleStrategy();
            if (strategy == null) {
                System.out.println("DEBUG: No role strategy found");
                return applicableRoles;
            }

            RoleMap itemRoles = strategy.getRoleMap(RoleType.Project);
            String folderPath = getFolderPath();
            
            System.out.println("DEBUG: Checking roles for folder path: " + folderPath);
            System.out.println("DEBUG: Total roles in system: " + itemRoles.getRoles().size());

            for (Role role : itemRoles.getRoles()) {
                String pattern = role.getPattern().pattern();
                System.out.println("DEBUG: Checking role '" + role.getName() + "' with pattern: " + pattern);
                
                try {
                    boolean matches = Pattern.matches(pattern, folderPath) ||
                                    Pattern.matches(pattern, folderPath + "/.*");
                    
                    System.out.println("DEBUG: Pattern matches: " + matches);
                    
                    if (matches) {
                        Set<String> assignments = itemRoles.getGrantedRoles().get(role);
                        if (assignments != null) {
                            applicableRoles.put(role, new HashSet<>(assignments));
                            System.out.println("DEBUG: Added role '" + role.getName() + "' with " + assignments.size() + " assignments");
                        } else {
                            applicableRoles.put(role, new HashSet<>());
                            System.out.println("DEBUG: Added role '" + role.getName() + "' with no assignments");
                        }
                    }
                } catch (PatternSyntaxException e) {
                    System.err.println("DEBUG: Invalid pattern for role " + role.getName() + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("Error getting applicable roles: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("DEBUG: Returning " + applicableRoles.size() + " applicable roles");
        return applicableRoles;
    }

    /**
     * Gets all available permissions for folder items
     */
    public List<Permission> getAvailablePermissions() {
        List<Permission> permissions = new ArrayList<>();

        // Add Overall permissions (essential for basic Jenkins access)
        permissions.addAll(Arrays.asList(
            Jenkins.READ,           // Overall/Read - CRITICAL for Jenkins access
            Jenkins.ADMINISTER      // Overall/Administer
        ));

        // Add common folder/job permissions
        permissions.addAll(Arrays.asList(
            hudson.model.Item.READ,
            hudson.model.Item.CONFIGURE,
            hudson.model.Item.DELETE,
            hudson.model.Item.BUILD,
            hudson.model.Item.WORKSPACE,
            hudson.model.Item.CANCEL,
            hudson.model.Item.DISCOVER,     // CRITICAL for folder visibility
            hudson.model.Item.CREATE
        ));

        // Add Run permissions if available
        try {
            permissions.add(hudson.model.Run.DELETE);
            permissions.add(hudson.model.Run.UPDATE);
        } catch (Exception e) {
            // These might not be available in all Jenkins versions
        }

        // Add View permissions
        try {
            permissions.add(hudson.model.View.READ);
            permissions.add(hudson.model.View.CONFIGURE);
            permissions.add(hudson.model.View.CREATE);
            permissions.add(hudson.model.View.DELETE);
        } catch (Exception e) {
            // These might not be available in all Jenkins versions
        }

        return permissions;
    }

    /**
     * Gets a human-readable name for a permission
     */
    public String getPermissionDisplayName(Permission permission) {
        if (permission == null) return "Unknown";
        
        // Extract the last part of the permission ID for display
        String id = permission.getId();
        if (id.contains(".")) {
            return id.substring(id.lastIndexOf('.') + 1);
        }
        return id;
    }

    /**
     * Gets a safe HTML ID for a permission
     */
    public String getPermissionHtmlId(Permission permission) {
        if (permission == null) return "unknown";
        
        return permission.getId().replace(".", "_").replace("/", "_").replace(" ", "_");
    }

    /**
     * Gets predefined role templates with common permission sets
     */
    public Map<String, Set<String>> getRoleTemplates() {
        Map<String, Set<String>> templates = new HashMap<>();
        
        try {
            // Wayne Basic Access - can see and work in assigned folders only
            Set<String> wayneBasicPerms = new HashSet<>();
            wayneBasicPerms.add("jenkins.model.Jenkins.Read");      // CRITICAL: Overall/Read for Jenkins access
            wayneBasicPerms.add("hudson.model.Item.Read");          // Can read folder contents
            wayneBasicPerms.add("hudson.model.Item.Discover");      // CRITICAL: Can see this folder in lists
            wayneBasicPerms.add("hudson.model.Item.Build");         // Can trigger builds
            wayneBasicPerms.add("hudson.model.Item.Cancel");        // Can cancel builds
            wayneBasicPerms.add("hudson.model.Item.Workspace");     // Can access workspaces
            templates.put("Wayne Developer", wayneBasicPerms);
            
            // Read Only Access
            Set<String> readOnlyPerms = new HashSet<>();
            readOnlyPerms.add("jenkins.model.Jenkins.Read");        // Overall/Read for Jenkins access
            readOnlyPerms.add("hudson.model.Item.Read");            // Can read folder contents
            readOnlyPerms.add("hudson.model.Item.Discover");        // Can see this folder
            templates.put("Read Only", readOnlyPerms);
            
            // Full Developer Access
            Set<String> developerPerms = new HashSet<>();
            developerPerms.add("jenkins.model.Jenkins.Read");       // Overall/Read for Jenkins access
            developerPerms.add("hudson.model.Item.Read");
            developerPerms.add("hudson.model.Item.Build");
            developerPerms.add("hudson.model.Item.Cancel");
            developerPerms.add("hudson.model.Item.Workspace");
            developerPerms.add("hudson.model.Item.Discover");       // Can see this folder
            developerPerms.add("hudson.model.Item.Configure");      // Can configure jobs
            templates.put("Full Developer", developerPerms);
            
            // Folder Manager (can do everything in the folder)
            Set<String> managerPerms = new HashSet<>();
            managerPerms.add("jenkins.model.Jenkins.Read");         // Overall/Read for Jenkins access
            managerPerms.add("hudson.model.Item.Read");
            managerPerms.add("hudson.model.Item.Configure");
            managerPerms.add("hudson.model.Item.Build");
            managerPerms.add("hudson.model.Item.Cancel");
            managerPerms.add("hudson.model.Item.Delete");
            managerPerms.add("hudson.model.Item.Create");
            managerPerms.add("hudson.model.Item.Workspace");
            managerPerms.add("hudson.model.Item.Discover");         // Can see this folder
            managerPerms.add("hudson.model.Run.Delete");
            managerPerms.add("hudson.model.Run.Update");
            templates.put("Folder Manager", managerPerms);
            
        } catch (Exception e) {
            System.err.println("Error creating role templates: " + e.getMessage());
        }
        
        return templates;
    }

    /**
     * Creates a new role specific to this folder
     */
    @POST
    @RequirePOST
    public FormValidation doCreateFolderRole(
            StaplerRequest req,
            StaplerResponse rsp) throws IOException, ServletException {

        // Check permissions - allow folder managers or Jenkins admins
        checkFolderManagementPermission();

        // Get parameters manually from request
        String roleName = req.getParameter("roleName");
        String roleTemplate = req.getParameter("roleTemplate");
        String[] permissionsArray = req.getParameterValues("permissions");

        System.out.println("=== DEBUG: Form submission parameters ===");
        System.out.println("roleName: '" + roleName + "'");
        System.out.println("roleTemplate: '" + roleTemplate + "'");
        System.out.println("permissions: " + Arrays.toString(permissionsArray));

        if (roleName == null || roleName.trim().isEmpty()) {
            return FormValidation.error("Role name cannot be empty. Received: '" + roleName + "'");
        }

        RoleBasedAuthorizationStrategy strategy = getRoleStrategy();
        if (strategy == null) {
            return FormValidation.error("Role-based authorization is not enabled");
        }

        try {
            // Create pattern that matches this folder and its contents
            String folderPattern = "^" + Pattern.quote(getFolderPath()) + "($|/.*)";

            // Parse permissions from array OR template
            Set<String> permissionIds = new HashSet<>();
            
            // First, check if a template was selected
            if (roleTemplate != null && !roleTemplate.trim().isEmpty()) {
                Map<String, Set<String>> templates = getRoleTemplates();
                Set<String> templatePermissions = templates.get(roleTemplate.trim());
                if (templatePermissions != null) {
                    permissionIds.addAll(templatePermissions);
                    System.out.println("Applied template '" + roleTemplate + "' with permissions: " + templatePermissions);
                }
            }
            
            // Then, add any manually selected permissions (these can override template)
            if (permissionsArray != null) {
                permissionIds.addAll(Arrays.asList(permissionsArray));
                System.out.println("Added manual permissions: " + Arrays.toString(permissionsArray));
            }

            // If no permissions at all, provide a helpful error
            if (permissionIds.isEmpty()) {
                return FormValidation.error("No permissions selected. Please choose a template or select permissions manually.");
            }

            System.out.println("Creating role with pattern: " + folderPattern);
            System.out.println("Final permission IDs: " + permissionIds);

            // Create the role using the public constructor
            Role newRole = new Role(roleName.trim(), folderPattern, permissionIds, "Auto-generated role for folder: " + getFolderPath());

            // Add to role map
            RoleMap itemRoles = strategy.getRoleMap(RoleType.Project);
            itemRoles.addRole(newRole);

            // Save configuration
            Jenkins.get().save();

            System.out.println("Role created successfully: " + roleName);

            // Redirect back to the main page after successful creation
            rsp.sendRedirect(".");
            return FormValidation.ok("Role '" + roleName + "' created successfully with " + permissionIds.size() + " permissions");

        } catch (Exception e) {
            System.err.println("Error creating role: " + e.getMessage());
            e.printStackTrace();
            return FormValidation.error("Failed to create role: " + e.getMessage());
        }
    }

    /**
     * Assigns a user or group to a role for this folder
     */
    @POST
    @RequirePOST
    public FormValidation doAssignRole(
            StaplerRequest req,
            StaplerResponse rsp) throws IOException, ServletException {

        // Check permissions
        checkFolderManagementPermission();

        // Get parameters from request
        String roleName = req.getParameter("roleName");
        String userOrGroup = req.getParameter("userOrGroup");
        String type = req.getParameter("type");

        System.out.println("=== DEBUG: Assign Role Parameters ===");
        System.out.println("roleName: '" + roleName + "'");
        System.out.println("userOrGroup: '" + userOrGroup + "'");
        System.out.println("type: '" + type + "'");

        if (userOrGroup == null || userOrGroup.trim().isEmpty()) {
            return FormValidation.error("User/Group name cannot be empty");
        }

        if (roleName == null || roleName.trim().isEmpty()) {
            return FormValidation.error("Role name cannot be empty");
        }

        RoleBasedAuthorizationStrategy strategy = getRoleStrategy();
        if (strategy == null) {
            return FormValidation.error("Role-based authorization is not enabled");
        }

        try {
            RoleMap itemRoles = strategy.getRoleMap(RoleType.Project);
            Role role = itemRoles.getRole(roleName.trim());

            if (role == null) {
                return FormValidation.error("Role '" + roleName + "' not found");
            }

            // Assign using the string-based API
            itemRoles.assignRole(role, userOrGroup.trim());

            Jenkins.get().save();

            // Redirect back to the main page after successful assignment
            rsp.sendRedirect(".");
            return FormValidation.ok("Successfully assigned " + userOrGroup + " to role " + roleName);

        } catch (Exception e) {
            return FormValidation.error("Failed to assign role: " + e.getMessage());
        }
    }

    /**
     * Removes a user or group from a role
     */
    @POST
    @RequirePOST
    public FormValidation doUnassignRole(
            StaplerRequest req,
            StaplerResponse rsp) throws IOException, ServletException {

        // Check permissions
        checkFolderManagementPermission();

        // Get parameters from request
        String roleName = req.getParameter("roleName");
        String userOrGroup = req.getParameter("userOrGroup");
        String type = req.getParameter("type");

        if (userOrGroup == null || userOrGroup.trim().isEmpty()) {
            return FormValidation.error("User/Group name cannot be empty");
        }

        RoleBasedAuthorizationStrategy strategy = getRoleStrategy();
        if (strategy == null) {
            return FormValidation.error("Role-based authorization is not enabled");
        }

        try {
            RoleMap itemRoles = strategy.getRoleMap(RoleType.Project);
            Role role = itemRoles.getRole(roleName);

            if (role == null) {
                return FormValidation.error("Role '" + roleName + "' not found");
            }

            // Unassign using string-based API
            Set<String> currentAssignments = itemRoles.getGrantedRoles().get(role);
            if (currentAssignments != null && currentAssignments.contains(userOrGroup.trim())) {
                currentAssignments.remove(userOrGroup.trim());
                Jenkins.get().save();
            }

            // Redirect back to the main page after successful removal
            rsp.sendRedirect(".");
            return FormValidation.ok("Successfully removed " + userOrGroup + " from role " + roleName);

        } catch (Exception e) {
            return FormValidation.error("Failed to unassign role: " + e.getMessage());
        }
    }

    /**
     * Gets effective permissions for a specific user on this folder
     */
    public Map<Permission, Boolean> getUserPermissions(@QueryParameter String username) {
        Map<Permission, Boolean> userPermissions = new HashMap<>();

        if (username == null || username.trim().isEmpty()) {
            return userPermissions;
        }

        User user = User.getById(username.trim(), false);
        if (user == null) {
            return userPermissions;
        }

        for (Permission permission : getAvailablePermissions()) {
            boolean hasPermission = folder.getACL().hasPermission(
                user.impersonate(), permission);
            userPermissions.put(permission, hasPermission);
        }

        return userPermissions;
    }

    /**
     * Debug method to check what roles a user has
     */
    public String doCheckUserRoles(@QueryParameter String username) {
        if (username == null || username.trim().isEmpty()) {
            return "Please provide a username";
        }

        StringBuilder result = new StringBuilder();
        result.append("<h3>Role Analysis for User: ").append(username).append("</h3>");
        
        try {
            RoleBasedAuthorizationStrategy strategy = getRoleStrategy();
            if (strategy == null) {
                return result.append("<p>Error: Role-based authorization is not enabled</p>").toString();
            }

            RoleMap itemRoles = strategy.getRoleMap(RoleType.Project);
            String folderPath = getFolderPath();
            
            result.append("<p><strong>Folder Path:</strong> ").append(folderPath).append("</p>");
            result.append("<p><strong>Total Roles in System:</strong> ").append(itemRoles.getRoles().size()).append("</p>");
            
            result.append("<h4>All Roles and Their Assignments:</h4>");
            result.append("<table border='1' style='border-collapse: collapse;'>");
            result.append("<tr><th>Role Name</th><th>Pattern</th><th>Matches This Folder?</th><th>User Assigned?</th><th>All Assignments</th></tr>");
            
            boolean userHasAnyRole = false;
            
            for (Role role : itemRoles.getRoles()) {
                String roleName = role.getName();
                String pattern = role.getPattern().pattern();
                
                // Check if pattern matches this folder
                boolean patternMatches = false;
                try {
                    patternMatches = Pattern.matches(pattern, folderPath) || 
                                   Pattern.matches(pattern, folderPath + "/.*");
                } catch (Exception e) {
                    // Invalid pattern
                }
                
                // Check if user is assigned to this role
                Set<String> assignments = itemRoles.getGrantedRoles().get(role);
                boolean userAssigned = assignments != null && assignments.contains(username);
                
                if (userAssigned && patternMatches) {
                    userHasAnyRole = true;
                }
                
                result.append("<tr>");
                result.append("<td>").append(roleName).append("</td>");
                result.append("<td><code>").append(pattern).append("</code></td>");
                result.append("<td>").append(patternMatches ? "✅ YES" : "❌ NO").append("</td>");
                result.append("<td>").append(userAssigned ? "✅ YES" : "❌ NO").append("</td>");
                result.append("<td>");
                if (assignments != null && !assignments.isEmpty()) {
                    for (String assignment : assignments) {
                        result.append(assignment).append("<br/>");
                    }
                } else {
                    result.append("<em>No assignments</em>");
                }
                result.append("</td>");
                result.append("</tr>");
            }
            result.append("</table>");
            
            result.append("<h4>Summary for ").append(username).append(":</h4>");
            if (userHasAnyRole) {
                result.append("<p style='color: green;'><strong>✅ User should see this folder</strong></p>");
            } else {
                result.append("<p style='color: red;'><strong>❌ User should NOT see this folder</strong></p>");
                result.append("<p>Reasons user might not see the folder:</p>");
                result.append("<ul>");
                result.append("<li>User not assigned to any roles that match this folder</li>");
                result.append("<li>Role patterns don't match this folder path</li>");
                result.append("<li>User missing Overall/Read permission globally</li>");
                result.append("<li>Roles missing Item.Discover permission</li>");
                result.append("</ul>");
            }
            
            // Check user's effective permissions on this folder
            result.append("<h4>Effective Permissions for ").append(username).append(" on this folder:</h4>");
            User user = User.getById(username, false);
            if (user != null) {
                result.append("<ul>");
                for (Permission permission : getAvailablePermissions()) {
                    boolean hasPermission = folder.getACL().hasPermission(user.impersonate(), permission);
                    result.append("<li>").append(permission.getId()).append(": ")
                          .append(hasPermission ? "✅ GRANTED" : "❌ DENIED").append("</li>");
                }
                result.append("</ul>");
            } else {
                result.append("<p>User '").append(username).append("' not found in Jenkins</p>");
            }
            
        } catch (Exception e) {
            result.append("<p style='color: red;'>Error: ").append(e.getMessage()).append("</p>");
        }
        
        return result.toString();
    }

    /**
     * Deletes a role (if it only applies to this folder)
     */
    @POST
    @RequirePOST
    public FormValidation doDeleteRole(
            StaplerRequest req,
            StaplerResponse rsp) throws IOException, ServletException {

        // Check permissions
        checkFolderManagementPermission();

        String roleName = req.getParameter("roleName");

        if (roleName == null || roleName.trim().isEmpty()) {
            return FormValidation.error("Role name cannot be empty");
        }

        RoleBasedAuthorizationStrategy strategy = getRoleStrategy();
        if (strategy == null) {
            return FormValidation.error("Role-based authorization is not enabled");
        }

        try {
            RoleMap itemRoles = strategy.getRoleMap(RoleType.Project);
            Role role = itemRoles.getRole(roleName);

            if (role == null) {
                return FormValidation.error("Role '" + roleName + "' not found");
            }

            // Only allow deletion if the role pattern matches exactly this folder
            String expectedPattern = "^" + Pattern.quote(getFolderPath()) + "($|/.*)";
            if (!role.getPattern().pattern().equals(expectedPattern)) {
                return FormValidation.error("Cannot delete role '" + roleName + "' - it applies to other folders/items");
            }

            // Remove the role
            itemRoles.removeRole(role);
            Jenkins.get().save();

            // Redirect back to the main page after successful deletion
            rsp.sendRedirect(".");
            return FormValidation.ok("Successfully deleted role " + roleName);

        } catch (Exception e) {
            return FormValidation.error("Failed to delete role: " + e.getMessage());
        }
    }

    // Helper methods

    private RoleBasedAuthorizationStrategy getRoleStrategy() {
        Jenkins jenkins = Jenkins.get();
        if (jenkins.getAuthorizationStrategy() instanceof RoleBasedAuthorizationStrategy) {
            return (RoleBasedAuthorizationStrategy) jenkins.getAuthorizationStrategy();
        }
        return null;
    }

    /**
     * Check if current user can manage folder permissions
     */
    private boolean canManageFolderPermissions() {
        try {
            // Option 1: Jenkins administrator (most permissive)
            if (Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                return true;
            }

            // Option 2: Folder configure permission (folder-level management)
            if (folder.hasPermission(hudson.model.Item.CONFIGURE)) {
                return true;
            }

            // Option 3: Can manage users (if you want HR/user managers to assign roles)
            // if (Jenkins.get().hasPermission(Jenkins.MANAGE)) {
            //     return true;
            // }

            return false;
        } catch (Exception e) {
            System.err.println("Error checking folder management permissions: " + e.getMessage());
            return false;
        }
    }

    /**
     * Check folder management permissions and throw exception if denied
     */
    private void checkFolderManagementPermission() throws IOException {
        if (!canManageFolderPermissions()) {
            throw new IOException("Access denied. You need either Jenkins Administrator permission or Configure permission on this folder.");
        }
    }

    /**
     * Factory class to add the permissions action to folders
     */
    @Extension
    public static class FolderPermissionsActionFactory extends TransientActionFactory<Folder> {

        @Override
        public Class<Folder> type() {
            return Folder.class;
        }

        @Nonnull
        @Override
        public Collection<? extends Action> createFor(@Nonnull Folder target) {
            // Always add the action if role-based strategy is enabled
            Jenkins jenkins = Jenkins.get();
            if (jenkins.getAuthorizationStrategy() instanceof RoleBasedAuthorizationStrategy) {
                return Collections.singletonList(new FolderPermissionsAction(target));
            }
            return Collections.emptyList();
        }
    }
}
