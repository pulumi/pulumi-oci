# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins as _builtins
import warnings
import sys
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict, TypeAlias
else:
    from typing_extensions import NotRequired, TypedDict, TypeAlias
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = ['DbmulticloudMultiCloudResourceDiscoveryArgs', 'DbmulticloudMultiCloudResourceDiscovery']

@pulumi.input_type
class DbmulticloudMultiCloudResourceDiscoveryArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[_builtins.str],
                 display_name: pulumi.Input[_builtins.str],
                 oracle_db_connector_id: pulumi.Input[_builtins.str],
                 resource_type: pulumi.Input[_builtins.str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None):
        """
        The set of arguments for constructing a DbmulticloudMultiCloudResourceDiscovery resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Discovered Resource.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) Display name of Discovered Resource.
        :param pulumi.Input[_builtins.str] oracle_db_connector_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of Oracle DB Connector.
        :param pulumi.Input[_builtins.str] resource_type: (Updatable) Resource Type to discover.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "oracle_db_connector_id", oracle_db_connector_id)
        pulumi.set(__self__, "resource_type", resource_type)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Discovered Resource.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) Display name of Discovered Resource.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="oracleDbConnectorId")
    def oracle_db_connector_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of Oracle DB Connector.
        """
        return pulumi.get(self, "oracle_db_connector_id")

    @oracle_db_connector_id.setter
    def oracle_db_connector_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "oracle_db_connector_id", value)

    @_builtins.property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) Resource Type to discover.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "resource_type")

    @resource_type.setter
    def resource_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "resource_type", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)


@pulumi.input_type
class _DbmulticloudMultiCloudResourceDiscoveryState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 last_modification: Optional[pulumi.Input[_builtins.str]] = None,
                 lifecycle_state_details: Optional[pulumi.Input[_builtins.str]] = None,
                 oracle_db_connector_id: Optional[pulumi.Input[_builtins.str]] = None,
                 resource_type: Optional[pulumi.Input[_builtins.str]] = None,
                 resources: Optional[pulumi.Input[Sequence[pulumi.Input['DbmulticloudMultiCloudResourceDiscoveryResourceArgs']]]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None,
                 time_updated: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering DbmulticloudMultiCloudResourceDiscovery resources.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Discovered Resource.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[_builtins.str] display_name: (Updatable) Display name of Discovered Resource.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[_builtins.str] last_modification: Description of the latest modification of the Multi Cloud Discovery Resource.
        :param pulumi.Input[_builtins.str] lifecycle_state_details: Description of the current lifecycle state in more detail.
        :param pulumi.Input[_builtins.str] oracle_db_connector_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of Oracle DB Connector.
        :param pulumi.Input[_builtins.str] resource_type: (Updatable) Resource Type to discover.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[Sequence[pulumi.Input['DbmulticloudMultiCloudResourceDiscoveryResourceArgs']]] resources: List of All Discovered resources.
        :param pulumi.Input[_builtins.str] state: The current lifecycle state of the discovered resource.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[_builtins.str] time_created: Time when the Multi Cloud Discovery Resource was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        :param pulumi.Input[_builtins.str] time_updated: Time when the Multi Cloud Discovery Resource was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if last_modification is not None:
            pulumi.set(__self__, "last_modification", last_modification)
        if lifecycle_state_details is not None:
            pulumi.set(__self__, "lifecycle_state_details", lifecycle_state_details)
        if oracle_db_connector_id is not None:
            pulumi.set(__self__, "oracle_db_connector_id", oracle_db_connector_id)
        if resource_type is not None:
            pulumi.set(__self__, "resource_type", resource_type)
        if resources is not None:
            pulumi.set(__self__, "resources", resources)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Discovered Resource.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "defined_tags", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Display name of Discovered Resource.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "freeform_tags", value)

    @_builtins.property
    @pulumi.getter(name="lastModification")
    def last_modification(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Description of the latest modification of the Multi Cloud Discovery Resource.
        """
        return pulumi.get(self, "last_modification")

    @last_modification.setter
    def last_modification(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "last_modification", value)

    @_builtins.property
    @pulumi.getter(name="lifecycleStateDetails")
    def lifecycle_state_details(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Description of the current lifecycle state in more detail.
        """
        return pulumi.get(self, "lifecycle_state_details")

    @lifecycle_state_details.setter
    def lifecycle_state_details(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "lifecycle_state_details", value)

    @_builtins.property
    @pulumi.getter(name="oracleDbConnectorId")
    def oracle_db_connector_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of Oracle DB Connector.
        """
        return pulumi.get(self, "oracle_db_connector_id")

    @oracle_db_connector_id.setter
    def oracle_db_connector_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "oracle_db_connector_id", value)

    @_builtins.property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Resource Type to discover.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "resource_type")

    @resource_type.setter
    def resource_type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "resource_type", value)

    @_builtins.property
    @pulumi.getter
    def resources(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['DbmulticloudMultiCloudResourceDiscoveryResourceArgs']]]]:
        """
        List of All Discovered resources.
        """
        return pulumi.get(self, "resources")

    @resources.setter
    def resources(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['DbmulticloudMultiCloudResourceDiscoveryResourceArgs']]]]):
        pulumi.set(self, "resources", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The current lifecycle state of the discovered resource.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @system_tags.setter
    def system_tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "system_tags", value)

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Time when the Multi Cloud Discovery Resource was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_created", value)

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Time when the Multi Cloud Discovery Resource was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_updated", value)


@pulumi.type_token("oci:oci/dbmulticloudMultiCloudResourceDiscovery:DbmulticloudMultiCloudResourceDiscovery")
class DbmulticloudMultiCloudResourceDiscovery(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 oracle_db_connector_id: Optional[pulumi.Input[_builtins.str]] = None,
                 resource_type: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Multi Cloud Resource Discovery resource in Oracle Cloud Infrastructure Dbmulticloud service.

        Discover Azure Vaults and Keys based on the provided information.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_multi_cloud_resource_discovery = oci.oci.DbmulticloudMultiCloudResourceDiscovery("test_multi_cloud_resource_discovery",
            compartment_id=compartment_id,
            display_name=multi_cloud_resource_discovery_display_name,
            oracle_db_connector_id=test_oracle_db_connector["id"],
            resource_type=multi_cloud_resource_discovery_resource_type,
            defined_tags={
                "Operations.CostCenter": "42",
            },
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        MultiCloudResourceDiscoveries can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:oci/dbmulticloudMultiCloudResourceDiscovery:DbmulticloudMultiCloudResourceDiscovery test_multi_cloud_resource_discovery "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Discovered Resource.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[_builtins.str] display_name: (Updatable) Display name of Discovered Resource.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[_builtins.str] oracle_db_connector_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of Oracle DB Connector.
        :param pulumi.Input[_builtins.str] resource_type: (Updatable) Resource Type to discover.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: DbmulticloudMultiCloudResourceDiscoveryArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Multi Cloud Resource Discovery resource in Oracle Cloud Infrastructure Dbmulticloud service.

        Discover Azure Vaults and Keys based on the provided information.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_multi_cloud_resource_discovery = oci.oci.DbmulticloudMultiCloudResourceDiscovery("test_multi_cloud_resource_discovery",
            compartment_id=compartment_id,
            display_name=multi_cloud_resource_discovery_display_name,
            oracle_db_connector_id=test_oracle_db_connector["id"],
            resource_type=multi_cloud_resource_discovery_resource_type,
            defined_tags={
                "Operations.CostCenter": "42",
            },
            freeform_tags={
                "Department": "Finance",
            })
        ```

        ## Import

        MultiCloudResourceDiscoveries can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:oci/dbmulticloudMultiCloudResourceDiscovery:DbmulticloudMultiCloudResourceDiscovery test_multi_cloud_resource_discovery "id"
        ```

        :param str resource_name: The name of the resource.
        :param DbmulticloudMultiCloudResourceDiscoveryArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(DbmulticloudMultiCloudResourceDiscoveryArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
                 oracle_db_connector_id: Optional[pulumi.Input[_builtins.str]] = None,
                 resource_type: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = DbmulticloudMultiCloudResourceDiscoveryArgs.__new__(DbmulticloudMultiCloudResourceDiscoveryArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["defined_tags"] = defined_tags
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["freeform_tags"] = freeform_tags
            if oracle_db_connector_id is None and not opts.urn:
                raise TypeError("Missing required property 'oracle_db_connector_id'")
            __props__.__dict__["oracle_db_connector_id"] = oracle_db_connector_id
            if resource_type is None and not opts.urn:
                raise TypeError("Missing required property 'resource_type'")
            __props__.__dict__["resource_type"] = resource_type
            __props__.__dict__["last_modification"] = None
            __props__.__dict__["lifecycle_state_details"] = None
            __props__.__dict__["resources"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(DbmulticloudMultiCloudResourceDiscovery, __self__).__init__(
            'oci:oci/dbmulticloudMultiCloudResourceDiscovery:DbmulticloudMultiCloudResourceDiscovery',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            display_name: Optional[pulumi.Input[_builtins.str]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            last_modification: Optional[pulumi.Input[_builtins.str]] = None,
            lifecycle_state_details: Optional[pulumi.Input[_builtins.str]] = None,
            oracle_db_connector_id: Optional[pulumi.Input[_builtins.str]] = None,
            resource_type: Optional[pulumi.Input[_builtins.str]] = None,
            resources: Optional[pulumi.Input[Sequence[pulumi.Input[Union['DbmulticloudMultiCloudResourceDiscoveryResourceArgs', 'DbmulticloudMultiCloudResourceDiscoveryResourceArgsDict']]]]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]]] = None,
            time_created: Optional[pulumi.Input[_builtins.str]] = None,
            time_updated: Optional[pulumi.Input[_builtins.str]] = None) -> 'DbmulticloudMultiCloudResourceDiscovery':
        """
        Get an existing DbmulticloudMultiCloudResourceDiscovery resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] compartment_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Discovered Resource.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        :param pulumi.Input[_builtins.str] display_name: (Updatable) Display name of Discovered Resource.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] freeform_tags: (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        :param pulumi.Input[_builtins.str] last_modification: Description of the latest modification of the Multi Cloud Discovery Resource.
        :param pulumi.Input[_builtins.str] lifecycle_state_details: Description of the current lifecycle state in more detail.
        :param pulumi.Input[_builtins.str] oracle_db_connector_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of Oracle DB Connector.
        :param pulumi.Input[_builtins.str] resource_type: (Updatable) Resource Type to discover.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[Sequence[pulumi.Input[Union['DbmulticloudMultiCloudResourceDiscoveryResourceArgs', 'DbmulticloudMultiCloudResourceDiscoveryResourceArgsDict']]]] resources: List of All Discovered resources.
        :param pulumi.Input[_builtins.str] state: The current lifecycle state of the discovered resource.
        :param pulumi.Input[Mapping[str, pulumi.Input[_builtins.str]]] system_tags: System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[_builtins.str] time_created: Time when the Multi Cloud Discovery Resource was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        :param pulumi.Input[_builtins.str] time_updated: Time when the Multi Cloud Discovery Resource was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _DbmulticloudMultiCloudResourceDiscoveryState.__new__(_DbmulticloudMultiCloudResourceDiscoveryState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["last_modification"] = last_modification
        __props__.__dict__["lifecycle_state_details"] = lifecycle_state_details
        __props__.__dict__["oracle_db_connector_id"] = oracle_db_connector_id
        __props__.__dict__["resource_type"] = resource_type
        __props__.__dict__["resources"] = resources
        __props__.__dict__["state"] = state
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return DbmulticloudMultiCloudResourceDiscovery(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains Discovered Resource.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Display name of Discovered Resource.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="lastModification")
    def last_modification(self) -> pulumi.Output[_builtins.str]:
        """
        Description of the latest modification of the Multi Cloud Discovery Resource.
        """
        return pulumi.get(self, "last_modification")

    @_builtins.property
    @pulumi.getter(name="lifecycleStateDetails")
    def lifecycle_state_details(self) -> pulumi.Output[_builtins.str]:
        """
        Description of the current lifecycle state in more detail.
        """
        return pulumi.get(self, "lifecycle_state_details")

    @_builtins.property
    @pulumi.getter(name="oracleDbConnectorId")
    def oracle_db_connector_id(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of Oracle DB Connector.
        """
        return pulumi.get(self, "oracle_db_connector_id")

    @_builtins.property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Resource Type to discover.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "resource_type")

    @_builtins.property
    @pulumi.getter
    def resources(self) -> pulumi.Output[Sequence['outputs.DbmulticloudMultiCloudResourceDiscoveryResource']]:
        """
        List of All Discovered resources.
        """
        return pulumi.get(self, "resources")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        """
        The current lifecycle state of the discovered resource.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> pulumi.Output[Mapping[str, _builtins.str]]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[_builtins.str]:
        """
        Time when the Multi Cloud Discovery Resource was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[_builtins.str]:
        """
        Time when the Multi Cloud Discovery Resource was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        return pulumi.get(self, "time_updated")

