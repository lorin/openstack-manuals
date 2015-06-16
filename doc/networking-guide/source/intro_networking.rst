==========================
Introduction to networking
==========================

The OpenStack Networking service provides an API that allows users to
set up and define network connectivity and addressing in the
cloud. The project code-name for Networking services is neutron.
OpenStack Networking handles the creation and management of a virtual
networking infrastructure, including networks, switches, subnets, and
routers for devices managed by the OpenStack Compute service
(nova). Advanced services such as firewalls or virtual private
networks (VPNs) can also be used.

OpenStack Networking consists of the neutron-server, a database for
persistent storage, and any number of plug-in agents, which provide
other services such as interfacing with native Linux networking
mechanisms, external devices, or SDN controllers.

OpenStack Networking is entirely standalone and can be deployed to a
dedicated host. If your deployment uses a controller host to run
centralized Compute components, you can deploy the Networking server
to that specific host instead.

OpenStack Networking integrates with various other OpenStack
components:

* OpenStack Identity (keystone) is used for authentication and
  authorization of API requests.

* OpenStack Compute (nova) is used to plug each virtual
  NIC on the VM into a particular network.

* OpenStack dashboard (horizon) is used by administrators and tenant users to
  create and manage network services through a web-based graphical
  interface.

.. toctree::
   :maxdepth: 2

   intro_basic_networking.rst
   intro_networking_components.rst
   intro_tunnel_technologies.rst
   intro_network_namespaces.rst
   intro_network_address_translation.rst
   intro_iptables.rst
