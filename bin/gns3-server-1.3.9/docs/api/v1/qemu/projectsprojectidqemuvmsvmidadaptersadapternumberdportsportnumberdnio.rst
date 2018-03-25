/v1/projects/{project_id}/qemu/vms/{vm_id}/adapters/{adapter_number:\d+}/ports/{port_number:\d+}/nio
----------------------------------------------------------------------------------------------------------------------

.. contents::

POST /v1/projects/**{project_id}**/qemu/vms/**{vm_id}**/adapters/**{adapter_number:\d+}**/ports/**{port_number:\d+}**/nio
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Add a NIO to a Qemu.instance

Parameters
**********
- **project_id**: UUID for the project
- **adapter_number**: Network adapter where the nio is located
- **port_number**: Port on the adapter (always 0)
- **vm_id**: UUID for the instance

Response status codes
**********************
- **400**: Invalid request
- **201**: NIO created
- **404**: Instance doesn't exist

Sample session
***************


.. literalinclude:: ../../examples/post_projectsprojectidqemuvmsvmidadaptersadapternumberdportsportnumberdnio.txt


DELETE /v1/projects/**{project_id}**/qemu/vms/**{vm_id}**/adapters/**{adapter_number:\d+}**/ports/**{port_number:\d+}**/nio
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Remove a NIO from a Qemu.instance

Parameters
**********
- **project_id**: UUID for the project
- **adapter_number**: Network adapter where the nio is located
- **port_number**: Port on the adapter (always 0)
- **vm_id**: UUID for the instance

Response status codes
**********************
- **400**: Invalid request
- **404**: Instance doesn't exist
- **204**: NIO deleted

Sample session
***************


.. literalinclude:: ../../examples/delete_projectsprojectidqemuvmsvmidadaptersadapternumberdportsportnumberdnio.txt

