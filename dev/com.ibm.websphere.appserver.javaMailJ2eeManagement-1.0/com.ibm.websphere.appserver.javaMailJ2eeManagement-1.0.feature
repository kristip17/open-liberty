-include= ~../cnf/resources/bnd/feature.props
symbolicName=com.ibm.websphere.appserver.javaMailJ2eeManagement-1.0
IBM-App-ForceRestart: install, \
 uninstall
IBM-Provision-Capability: \
  osgi.identity; filter:="(&(type=osgi.subsystem.feature)(|(osgi.identity=com.ibm.websphere.appserver.javaMail-1.5)(osgi.identity=com.ibm.websphere.appserver.javaMail-1.6)))", \
  osgi.identity; filter:="(&(type=osgi.subsystem.feature)(osgi.identity=com.ibm.websphere.appserver.j2eeManagement-1.1))"
IBM-Install-Policy: when-satisfied
-bundles=com.ibm.ws.javamail.management.j2ee
kind=ga
edition=base
