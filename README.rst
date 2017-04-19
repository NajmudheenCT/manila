===================
EMC Fork for MANILA
===================


This fork contains the downstream bug fixes and features for Dell EMC Manila drivers, including the ones for Unity and VNX products.


Releases
--------

* The ``Unity`` Manila driver is available on following branch(es):
    * emc/newton (Version: 1.x.x)
    * emc/mitaka (Version: 0.9.x)

* The ``VNX`` Manila driver is available on following branch(es):
    * emc/newton (Version: 2.1.x)


Deploy
------

There are two ways to deploy the EMC downstream driver.

* Switch to the forked repository from EMC.

  This is the recommend approach.  It saves the effort of selecting and
  copying individual files.

* Copy the files in following list to the corresponding location of your manila
  install:

    * ``manila/exception.py``
    * ``manila/share/drivers/emc/*.py``
    * ``manila/share/drivers/emc/plugins/*.py``
    * ``manila/share/drivers/emc/plugins/unity/*.py`` to deploy Unity driver
    * ``manila/share/drivers/emc/plugins/vnx/*.py`` to deploy VNX driver
    * ``requirements.txt``
    * ``setup.cfg``

* After copying the files, you need to reinstall manila.
  Under your manila source code folder, run:

.. code-block:: bash

    python setup.py install

* And restart your manila service to enable the change.


Configuration
-------------

**NOTE: Some options are renamed from Newton.**

Rename driver options for Unity/VNX, the old ones are deprecated:

========================  ======================  ====================
Old options               New in Unity            New in VNX
========================  ======================  ====================
emc_nas_pool_names        unity_share_data_pools  vnx_share_data_pools
emc_nas_server_pool       unity_server_meta_pool  N/A
emc_interface_ports       unity_ethernet_ports    vnx_ethernet_ports
emc_nas_server_container  unity_server_container  vnx_server_container
========================  ======================  ====================


======
MANILA
======

You have come across an OpenStack shared file system service.  It has
identified itself as "Manila."  It was abstracted from the Cinder
project.

* Wiki: https://wiki.openstack.org/Manila
* Developer docs: http://docs.openstack.org/developer/manila

Getting Started
---------------

If you'd like to run from the master branch, you can clone the git repo:

    git clone https://github.com/openstack/manila.git

For developer information please see
`HACKING.rst <https://github.com/openstack/manila/blob/master/HACKING.rst>`_

You can raise bugs here http://bugs.launchpad.net/manila

Python client
-------------

https://github.com/openstack/python-manilaclient.git
