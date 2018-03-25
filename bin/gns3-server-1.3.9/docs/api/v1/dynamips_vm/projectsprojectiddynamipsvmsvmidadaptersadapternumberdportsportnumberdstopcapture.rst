/v1/projects/{project_id}/dynamips/vms/{vm_id}/adapters/{adapter_number:\d+}/ports/{port_number:\d+}/stop_capture
----------------------------------------------------------------------------------------------------------------------

.. contents::

POST /v1/projects/**{project_id}**/dynamips/vms/**{vm_id}**/adapters/**{adapter_number:\d+}**/ports/**{port_number:\d+}**/stop_capture
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Stop a packet capture on a Dynamips VM instance

Parameters
**********
- **project_id**: UUID for the project
- **adapter_number**: Adapter to stop a packet capture
- **port_number**: Port on the adapter (always 0)
- **vm_id**: UUID for the instance

Response status codes
**********************
- **400**: Invalid request
- **404**: Instance doesn't exist
- **204**: Capture stopped

