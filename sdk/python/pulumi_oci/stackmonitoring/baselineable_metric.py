# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['BaselineableMetricArgs', 'BaselineableMetric']

@pulumi.input_type
class BaselineableMetricArgs:
    def __init__(__self__, *,
                 column: pulumi.Input[str],
                 compartment_id: pulumi.Input[str],
                 namespace: pulumi.Input[str],
                 resource_group: pulumi.Input[str],
                 name: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a BaselineableMetric resource.
        :param pulumi.Input[str] column: (Updatable) metric column name
        :param pulumi.Input[str] compartment_id: (Updatable) OCID of the compartment
        :param pulumi.Input[str] namespace: (Updatable) namespace of the metric
        :param pulumi.Input[str] resource_group: (Updatable) Resource group of the metric
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[str] name: (Updatable) name of the metric
        """
        pulumi.set(__self__, "column", column)
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "namespace", namespace)
        pulumi.set(__self__, "resource_group", resource_group)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def column(self) -> pulumi.Input[str]:
        """
        (Updatable) metric column name
        """
        return pulumi.get(self, "column")

    @column.setter
    def column(self, value: pulumi.Input[str]):
        pulumi.set(self, "column", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        (Updatable) OCID of the compartment
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter
    def namespace(self) -> pulumi.Input[str]:
        """
        (Updatable) namespace of the metric
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: pulumi.Input[str]):
        pulumi.set(self, "namespace", value)

    @property
    @pulumi.getter(name="resourceGroup")
    def resource_group(self) -> pulumi.Input[str]:
        """
        (Updatable) Resource group of the metric


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "resource_group")

    @resource_group.setter
    def resource_group(self, value: pulumi.Input[str]):
        pulumi.set(self, "resource_group", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) name of the metric
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)


@pulumi.input_type
class _BaselineableMetricState:
    def __init__(__self__, *,
                 column: Optional[pulumi.Input[str]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 created_by: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 is_out_of_box: Optional[pulumi.Input[bool]] = None,
                 last_updated_by: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 namespace: Optional[pulumi.Input[str]] = None,
                 resource_group: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 tenancy_id: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_last_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering BaselineableMetric resources.
        :param pulumi.Input[str] column: (Updatable) metric column name
        :param pulumi.Input[str] compartment_id: (Updatable) OCID of the compartment
        :param pulumi.Input[str] created_by: Created user id
        :param pulumi.Input[Mapping[str, Any]] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[bool] is_out_of_box: Is the metric created out of box, default false
        :param pulumi.Input[str] last_updated_by: last Updated user id
        :param pulumi.Input[str] name: (Updatable) name of the metric
        :param pulumi.Input[str] namespace: (Updatable) namespace of the metric
        :param pulumi.Input[str] resource_group: (Updatable) Resource group of the metric
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[str] state: The current lifecycle state of the metric extension
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] tenancy_id: OCID of the tenancy
        :param pulumi.Input[str] time_created: creation date
        :param pulumi.Input[str] time_last_updated: last updated time
        """
        if column is not None:
            pulumi.set(__self__, "column", column)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by is not None:
            pulumi.set(__self__, "created_by", created_by)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if is_out_of_box is not None:
            pulumi.set(__self__, "is_out_of_box", is_out_of_box)
        if last_updated_by is not None:
            pulumi.set(__self__, "last_updated_by", last_updated_by)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if namespace is not None:
            pulumi.set(__self__, "namespace", namespace)
        if resource_group is not None:
            pulumi.set(__self__, "resource_group", resource_group)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if tenancy_id is not None:
            pulumi.set(__self__, "tenancy_id", tenancy_id)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_last_updated is not None:
            pulumi.set(__self__, "time_last_updated", time_last_updated)

    @property
    @pulumi.getter
    def column(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) metric column name
        """
        return pulumi.get(self, "column")

    @column.setter
    def column(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "column", value)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) OCID of the compartment
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> Optional[pulumi.Input[str]]:
        """
        Created user id
        """
        return pulumi.get(self, "created_by")

    @created_by.setter
    def created_by(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "created_by", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="isOutOfBox")
    def is_out_of_box(self) -> Optional[pulumi.Input[bool]]:
        """
        Is the metric created out of box, default false
        """
        return pulumi.get(self, "is_out_of_box")

    @is_out_of_box.setter
    def is_out_of_box(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_out_of_box", value)

    @property
    @pulumi.getter(name="lastUpdatedBy")
    def last_updated_by(self) -> Optional[pulumi.Input[str]]:
        """
        last Updated user id
        """
        return pulumi.get(self, "last_updated_by")

    @last_updated_by.setter
    def last_updated_by(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "last_updated_by", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) name of the metric
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def namespace(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) namespace of the metric
        """
        return pulumi.get(self, "namespace")

    @namespace.setter
    def namespace(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "namespace", value)

    @property
    @pulumi.getter(name="resourceGroup")
    def resource_group(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Resource group of the metric


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "resource_group")

    @resource_group.setter
    def resource_group(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "resource_group", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current lifecycle state of the metric extension
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @system_tags.setter
    def system_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "system_tags", value)

    @property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> Optional[pulumi.Input[str]]:
        """
        OCID of the tenancy
        """
        return pulumi.get(self, "tenancy_id")

    @tenancy_id.setter
    def tenancy_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "tenancy_id", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        creation date
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeLastUpdated")
    def time_last_updated(self) -> Optional[pulumi.Input[str]]:
        """
        last updated time
        """
        return pulumi.get(self, "time_last_updated")

    @time_last_updated.setter
    def time_last_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_last_updated", value)


class BaselineableMetric(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 column: Optional[pulumi.Input[str]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 namespace: Optional[pulumi.Input[str]] = None,
                 resource_group: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Baselineable Metric resource in Oracle Cloud Infrastructure Stack Monitoring service.

        Creates the specified Baseline-able metric

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_baselineable_metric = oci.stack_monitoring.BaselineableMetric("testBaselineableMetric",
            column=var["baselineable_metric_column"],
            compartment_id=var["compartment_id"],
            namespace=var["baselineable_metric_namespace"],
            resource_group=var["baselineable_metric_resource_group"])
        ```

        ## Import

        BaselineableMetrics can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:StackMonitoring/baselineableMetric:BaselineableMetric test_baselineable_metric "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] column: (Updatable) metric column name
        :param pulumi.Input[str] compartment_id: (Updatable) OCID of the compartment
        :param pulumi.Input[str] name: (Updatable) name of the metric
        :param pulumi.Input[str] namespace: (Updatable) namespace of the metric
        :param pulumi.Input[str] resource_group: (Updatable) Resource group of the metric
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: BaselineableMetricArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Baselineable Metric resource in Oracle Cloud Infrastructure Stack Monitoring service.

        Creates the specified Baseline-able metric

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_baselineable_metric = oci.stack_monitoring.BaselineableMetric("testBaselineableMetric",
            column=var["baselineable_metric_column"],
            compartment_id=var["compartment_id"],
            namespace=var["baselineable_metric_namespace"],
            resource_group=var["baselineable_metric_resource_group"])
        ```

        ## Import

        BaselineableMetrics can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:StackMonitoring/baselineableMetric:BaselineableMetric test_baselineable_metric "id"
        ```

        :param str resource_name: The name of the resource.
        :param BaselineableMetricArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(BaselineableMetricArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 column: Optional[pulumi.Input[str]] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 namespace: Optional[pulumi.Input[str]] = None,
                 resource_group: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = BaselineableMetricArgs.__new__(BaselineableMetricArgs)

            if column is None and not opts.urn:
                raise TypeError("Missing required property 'column'")
            __props__.__dict__["column"] = column
            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["name"] = name
            if namespace is None and not opts.urn:
                raise TypeError("Missing required property 'namespace'")
            __props__.__dict__["namespace"] = namespace
            if resource_group is None and not opts.urn:
                raise TypeError("Missing required property 'resource_group'")
            __props__.__dict__["resource_group"] = resource_group
            __props__.__dict__["created_by"] = None
            __props__.__dict__["defined_tags"] = None
            __props__.__dict__["freeform_tags"] = None
            __props__.__dict__["is_out_of_box"] = None
            __props__.__dict__["last_updated_by"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["tenancy_id"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_last_updated"] = None
        super(BaselineableMetric, __self__).__init__(
            'oci:StackMonitoring/baselineableMetric:BaselineableMetric',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            column: Optional[pulumi.Input[str]] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            created_by: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            is_out_of_box: Optional[pulumi.Input[bool]] = None,
            last_updated_by: Optional[pulumi.Input[str]] = None,
            name: Optional[pulumi.Input[str]] = None,
            namespace: Optional[pulumi.Input[str]] = None,
            resource_group: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            tenancy_id: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_last_updated: Optional[pulumi.Input[str]] = None) -> 'BaselineableMetric':
        """
        Get an existing BaselineableMetric resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] column: (Updatable) metric column name
        :param pulumi.Input[str] compartment_id: (Updatable) OCID of the compartment
        :param pulumi.Input[str] created_by: Created user id
        :param pulumi.Input[Mapping[str, Any]] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[bool] is_out_of_box: Is the metric created out of box, default false
        :param pulumi.Input[str] last_updated_by: last Updated user id
        :param pulumi.Input[str] name: (Updatable) name of the metric
        :param pulumi.Input[str] namespace: (Updatable) namespace of the metric
        :param pulumi.Input[str] resource_group: (Updatable) Resource group of the metric
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[str] state: The current lifecycle state of the metric extension
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] tenancy_id: OCID of the tenancy
        :param pulumi.Input[str] time_created: creation date
        :param pulumi.Input[str] time_last_updated: last updated time
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _BaselineableMetricState.__new__(_BaselineableMetricState)

        __props__.__dict__["column"] = column
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["created_by"] = created_by
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["is_out_of_box"] = is_out_of_box
        __props__.__dict__["last_updated_by"] = last_updated_by
        __props__.__dict__["name"] = name
        __props__.__dict__["namespace"] = namespace
        __props__.__dict__["resource_group"] = resource_group
        __props__.__dict__["state"] = state
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["tenancy_id"] = tenancy_id
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_last_updated"] = time_last_updated
        return BaselineableMetric(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter
    def column(self) -> pulumi.Output[str]:
        """
        (Updatable) metric column name
        """
        return pulumi.get(self, "column")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        (Updatable) OCID of the compartment
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> pulumi.Output[str]:
        """
        Created user id
        """
        return pulumi.get(self, "created_by")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="isOutOfBox")
    def is_out_of_box(self) -> pulumi.Output[bool]:
        """
        Is the metric created out of box, default false
        """
        return pulumi.get(self, "is_out_of_box")

    @property
    @pulumi.getter(name="lastUpdatedBy")
    def last_updated_by(self) -> pulumi.Output[str]:
        """
        last Updated user id
        """
        return pulumi.get(self, "last_updated_by")

    @property
    @pulumi.getter
    def name(self) -> pulumi.Output[str]:
        """
        (Updatable) name of the metric
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def namespace(self) -> pulumi.Output[str]:
        """
        (Updatable) namespace of the metric
        """
        return pulumi.get(self, "namespace")

    @property
    @pulumi.getter(name="resourceGroup")
    def resource_group(self) -> pulumi.Output[str]:
        """
        (Updatable) Resource group of the metric


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "resource_group")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current lifecycle state of the metric extension
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> pulumi.Output[str]:
        """
        OCID of the tenancy
        """
        return pulumi.get(self, "tenancy_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        creation date
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeLastUpdated")
    def time_last_updated(self) -> pulumi.Output[str]:
        """
        last updated time
        """
        return pulumi.get(self, "time_last_updated")
