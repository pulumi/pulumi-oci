# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = ['CustomTableArgs', 'CustomTable']

@pulumi.input_type
class CustomTableArgs:
    def __init__(__self__, *,
                 compartment_id: pulumi.Input[str],
                 saved_custom_table: pulumi.Input['CustomTableSavedCustomTableArgs'],
                 saved_report_id: pulumi.Input[str]):
        """
        The set of arguments for constructing a CustomTable resource.
        :param pulumi.Input[str] compartment_id: The compartment OCID.
        :param pulumi.Input['CustomTableSavedCustomTableArgs'] saved_custom_table: (Updatable) The custom table for Cost Analysis UI rendering.
        :param pulumi.Input[str] saved_report_id: The associated saved report OCID.
        """
        pulumi.set(__self__, "compartment_id", compartment_id)
        pulumi.set(__self__, "saved_custom_table", saved_custom_table)
        pulumi.set(__self__, "saved_report_id", saved_report_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Input[str]:
        """
        The compartment OCID.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="savedCustomTable")
    def saved_custom_table(self) -> pulumi.Input['CustomTableSavedCustomTableArgs']:
        """
        (Updatable) The custom table for Cost Analysis UI rendering.
        """
        return pulumi.get(self, "saved_custom_table")

    @saved_custom_table.setter
    def saved_custom_table(self, value: pulumi.Input['CustomTableSavedCustomTableArgs']):
        pulumi.set(self, "saved_custom_table", value)

    @property
    @pulumi.getter(name="savedReportId")
    def saved_report_id(self) -> pulumi.Input[str]:
        """
        The associated saved report OCID.
        """
        return pulumi.get(self, "saved_report_id")

    @saved_report_id.setter
    def saved_report_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "saved_report_id", value)


@pulumi.input_type
class _CustomTableState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 saved_custom_table: Optional[pulumi.Input['CustomTableSavedCustomTableArgs']] = None,
                 saved_report_id: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering CustomTable resources.
        :param pulumi.Input[str] compartment_id: The compartment OCID.
        :param pulumi.Input['CustomTableSavedCustomTableArgs'] saved_custom_table: (Updatable) The custom table for Cost Analysis UI rendering.
        :param pulumi.Input[str] saved_report_id: The associated saved report OCID.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if saved_custom_table is not None:
            pulumi.set(__self__, "saved_custom_table", saved_custom_table)
        if saved_report_id is not None:
            pulumi.set(__self__, "saved_report_id", saved_report_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        The compartment OCID.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="savedCustomTable")
    def saved_custom_table(self) -> Optional[pulumi.Input['CustomTableSavedCustomTableArgs']]:
        """
        (Updatable) The custom table for Cost Analysis UI rendering.
        """
        return pulumi.get(self, "saved_custom_table")

    @saved_custom_table.setter
    def saved_custom_table(self, value: Optional[pulumi.Input['CustomTableSavedCustomTableArgs']]):
        pulumi.set(self, "saved_custom_table", value)

    @property
    @pulumi.getter(name="savedReportId")
    def saved_report_id(self) -> Optional[pulumi.Input[str]]:
        """
        The associated saved report OCID.
        """
        return pulumi.get(self, "saved_report_id")

    @saved_report_id.setter
    def saved_report_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "saved_report_id", value)


class CustomTable(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 saved_custom_table: Optional[pulumi.Input[pulumi.InputType['CustomTableSavedCustomTableArgs']]] = None,
                 saved_report_id: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Custom Table resource in Oracle Cloud Infrastructure Metering Computation service.

        Returns the created custom table.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_custom_table = oci.metering_computation.CustomTable("testCustomTable",
            compartment_id=var["compartment_id"],
            saved_custom_table=oci.metering_computation.CustomTableSavedCustomTableArgs(
                display_name=var["custom_table_saved_custom_table_display_name"],
                column_group_bies=var["custom_table_saved_custom_table_column_group_by"],
                compartment_depth=var["custom_table_saved_custom_table_compartment_depth"],
                group_by_tags=[oci.metering_computation.CustomTableSavedCustomTableGroupByTagArgs(
                    key=var["custom_table_saved_custom_table_group_by_tag_key"],
                    namespace=var["custom_table_saved_custom_table_group_by_tag_namespace"],
                    value=var["custom_table_saved_custom_table_group_by_tag_value"],
                )],
                row_group_bies=var["custom_table_saved_custom_table_row_group_by"],
                version=var["custom_table_saved_custom_table_version"],
            ),
            saved_report_id=oci_metering_computation_saved_report["test_saved_report"]["id"])
        ```

        ## Import

        CustomTables can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:MeteringComputation/customTable:CustomTable test_custom_table "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The compartment OCID.
        :param pulumi.Input[pulumi.InputType['CustomTableSavedCustomTableArgs']] saved_custom_table: (Updatable) The custom table for Cost Analysis UI rendering.
        :param pulumi.Input[str] saved_report_id: The associated saved report OCID.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: CustomTableArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Custom Table resource in Oracle Cloud Infrastructure Metering Computation service.

        Returns the created custom table.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_custom_table = oci.metering_computation.CustomTable("testCustomTable",
            compartment_id=var["compartment_id"],
            saved_custom_table=oci.metering_computation.CustomTableSavedCustomTableArgs(
                display_name=var["custom_table_saved_custom_table_display_name"],
                column_group_bies=var["custom_table_saved_custom_table_column_group_by"],
                compartment_depth=var["custom_table_saved_custom_table_compartment_depth"],
                group_by_tags=[oci.metering_computation.CustomTableSavedCustomTableGroupByTagArgs(
                    key=var["custom_table_saved_custom_table_group_by_tag_key"],
                    namespace=var["custom_table_saved_custom_table_group_by_tag_namespace"],
                    value=var["custom_table_saved_custom_table_group_by_tag_value"],
                )],
                row_group_bies=var["custom_table_saved_custom_table_row_group_by"],
                version=var["custom_table_saved_custom_table_version"],
            ),
            saved_report_id=oci_metering_computation_saved_report["test_saved_report"]["id"])
        ```

        ## Import

        CustomTables can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:MeteringComputation/customTable:CustomTable test_custom_table "id"
        ```

        :param str resource_name: The name of the resource.
        :param CustomTableArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(CustomTableArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 saved_custom_table: Optional[pulumi.Input[pulumi.InputType['CustomTableSavedCustomTableArgs']]] = None,
                 saved_report_id: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = CustomTableArgs.__new__(CustomTableArgs)

            if compartment_id is None and not opts.urn:
                raise TypeError("Missing required property 'compartment_id'")
            __props__.__dict__["compartment_id"] = compartment_id
            if saved_custom_table is None and not opts.urn:
                raise TypeError("Missing required property 'saved_custom_table'")
            __props__.__dict__["saved_custom_table"] = saved_custom_table
            if saved_report_id is None and not opts.urn:
                raise TypeError("Missing required property 'saved_report_id'")
            __props__.__dict__["saved_report_id"] = saved_report_id
        super(CustomTable, __self__).__init__(
            'oci:MeteringComputation/customTable:CustomTable',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            saved_custom_table: Optional[pulumi.Input[pulumi.InputType['CustomTableSavedCustomTableArgs']]] = None,
            saved_report_id: Optional[pulumi.Input[str]] = None) -> 'CustomTable':
        """
        Get an existing CustomTable resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: The compartment OCID.
        :param pulumi.Input[pulumi.InputType['CustomTableSavedCustomTableArgs']] saved_custom_table: (Updatable) The custom table for Cost Analysis UI rendering.
        :param pulumi.Input[str] saved_report_id: The associated saved report OCID.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _CustomTableState.__new__(_CustomTableState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["saved_custom_table"] = saved_custom_table
        __props__.__dict__["saved_report_id"] = saved_report_id
        return CustomTable(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        The compartment OCID.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="savedCustomTable")
    def saved_custom_table(self) -> pulumi.Output['outputs.CustomTableSavedCustomTable']:
        """
        (Updatable) The custom table for Cost Analysis UI rendering.
        """
        return pulumi.get(self, "saved_custom_table")

    @property
    @pulumi.getter(name="savedReportId")
    def saved_report_id(self) -> pulumi.Output[str]:
        """
        The associated saved report OCID.
        """
        return pulumi.get(self, "saved_report_id")
