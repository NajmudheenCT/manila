===================
EMC Fork for MANILA
===================


This fork contains the latest EMC drivers for Manila project.

Releases
--------

For now, the Unity Manila driver is available on following branch(es):

* emc/mitaka

Deploy
------

There are two ways to copy the EMC Unity driver.

* Switch to the forked repository from EMC.

  This is the recommend approach.  It saves the effort of selecting and
  copying individual files.

* Copy the files in following list to the corresponding location of your manila
  install:

    * manila/exception.py
    * manila/share/drivers/emc/driver.py
    * manila/share/drivers/emc/plugins/unity/__init__.py
    * manila/share/drivers/emc/plugins/unity/client.py
    * manila/share/drivers/emc/plugins/unity/connection.py
    * requirements.txt
    * setup.cfg

After copying the files, you need to reinstall manila.
Under your manila source code folder, run:

.. code-block:: bash

    python setup.py install

And restart your manila service to enable the change.


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
