mvn clean package -DskipTests -Dcheckstyle.skip=true
cp -rfp target/role-strategy.hpi ~/.jenkins/plugins/role-strategy.jpi
rm -rf  ~/.jenkins/plugins/role-strategy
jenkins-lts
