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

__all__ = ['ExportSetArgs', 'ExportSet']

@pulumi.input_type
class ExportSetArgs:
    def __init__(__self__, *,
                 mount_target_id: pulumi.Input[_builtins.str],
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 max_fs_stat_bytes: Optional[pulumi.Input[_builtins.str]] = None,
                 max_fs_stat_files: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a ExportSet resource.
        :param pulumi.Input[_builtins.str] mount_target_id: (Updatable) The OCID of the mount target that the export set is associated with
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
        :param pulumi.Input[_builtins.str] max_fs_stat_bytes: (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
        :param pulumi.Input[_builtins.str] max_fs_stat_files: (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'. 
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "mount_target_id", mount_target_id)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if max_fs_stat_bytes is not None:
            pulumi.set(__self__, "max_fs_stat_bytes", max_fs_stat_bytes)
        if max_fs_stat_files is not None:
            pulumi.set(__self__, "max_fs_stat_files", max_fs_stat_files)

    @_builtins.property
    @pulumi.getter(name="mountTargetId")
    def mount_target_id(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The OCID of the mount target that the export set is associated with
        """
        return pulumi.get(self, "mount_target_id")

    @mount_target_id.setter
    def mount_target_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "mount_target_id", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="maxFsStatBytes")
    def max_fs_stat_bytes(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
        """
        return pulumi.get(self, "max_fs_stat_bytes")

    @max_fs_stat_bytes.setter
    def max_fs_stat_bytes(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "max_fs_stat_bytes", value)

    @_builtins.property
    @pulumi.getter(name="maxFsStatFiles")
    def max_fs_stat_files(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'. 

        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "max_fs_stat_files")

    @max_fs_stat_files.setter
    def max_fs_stat_files(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "max_fs_stat_files", value)


@pulumi.input_type
class _ExportSetState:
    def __init__(__self__, *,
                 availability_domain: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 max_fs_stat_bytes: Optional[pulumi.Input[_builtins.str]] = None,
                 max_fs_stat_files: Optional[pulumi.Input[_builtins.str]] = None,
                 mount_target_id: Optional[pulumi.Input[_builtins.str]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None,
                 time_created: Optional[pulumi.Input[_builtins.str]] = None,
                 vcn_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering ExportSet resources.
        :param pulumi.Input[_builtins.str] availability_domain: The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
        :param pulumi.Input[_builtins.str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
        :param pulumi.Input[_builtins.str] max_fs_stat_bytes: (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
        :param pulumi.Input[_builtins.str] max_fs_stat_files: (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'. 
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] mount_target_id: (Updatable) The OCID of the mount target that the export set is associated with
        :param pulumi.Input[_builtins.str] state: The current state of the export set.
        :param pulumi.Input[_builtins.str] time_created: The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[_builtins.str] vcn_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
        """
        if availability_domain is not None:
            pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if max_fs_stat_bytes is not None:
            pulumi.set(__self__, "max_fs_stat_bytes", max_fs_stat_bytes)
        if max_fs_stat_files is not None:
            pulumi.set(__self__, "max_fs_stat_files", max_fs_stat_files)
        if mount_target_id is not None:
            pulumi.set(__self__, "mount_target_id", mount_target_id)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if vcn_id is not None:
            pulumi.set(__self__, "vcn_id", vcn_id)

    @_builtins.property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @availability_domain.setter
    def availability_domain(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "availability_domain", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "display_name", value)

    @_builtins.property
    @pulumi.getter(name="maxFsStatBytes")
    def max_fs_stat_bytes(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
        """
        return pulumi.get(self, "max_fs_stat_bytes")

    @max_fs_stat_bytes.setter
    def max_fs_stat_bytes(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "max_fs_stat_bytes", value)

    @_builtins.property
    @pulumi.getter(name="maxFsStatFiles")
    def max_fs_stat_files(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'. 

        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "max_fs_stat_files")

    @max_fs_stat_files.setter
    def max_fs_stat_files(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "max_fs_stat_files", value)

    @_builtins.property
    @pulumi.getter(name="mountTargetId")
    def mount_target_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The OCID of the mount target that the export set is associated with
        """
        return pulumi.get(self, "mount_target_id")

    @mount_target_id.setter
    def mount_target_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "mount_target_id", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The current state of the export set.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_created", value)

    @_builtins.property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
        """
        return pulumi.get(self, "vcn_id")

    @vcn_id.setter
    def vcn_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "vcn_id", value)


@pulumi.type_token("oci:FileStorage/exportSet:ExportSet")
class ExportSet(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 max_fs_stat_bytes: Optional[pulumi.Input[_builtins.str]] = None,
                 max_fs_stat_files: Optional[pulumi.Input[_builtins.str]] = None,
                 mount_target_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_export_set = oci.filestorage.ExportSet("test_export_set",
            mount_target_id=test_mount_target["id"],
            display_name=export_set_name,
            max_fs_stat_bytes="23843202333",
            max_fs_stat_files="223442")
        ```

        ## Import

        ExportSets can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:FileStorage/exportSet:ExportSet test_export_set "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
        :param pulumi.Input[_builtins.str] max_fs_stat_bytes: (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
        :param pulumi.Input[_builtins.str] max_fs_stat_files: (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'. 
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] mount_target_id: (Updatable) The OCID of the mount target that the export set is associated with
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ExportSetArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_export_set = oci.filestorage.ExportSet("test_export_set",
            mount_target_id=test_mount_target["id"],
            display_name=export_set_name,
            max_fs_stat_bytes="23843202333",
            max_fs_stat_files="223442")
        ```

        ## Import

        ExportSets can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:FileStorage/exportSet:ExportSet test_export_set "id"
        ```

        :param str resource_name: The name of the resource.
        :param ExportSetArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ExportSetArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 display_name: Optional[pulumi.Input[_builtins.str]] = None,
                 max_fs_stat_bytes: Optional[pulumi.Input[_builtins.str]] = None,
                 max_fs_stat_files: Optional[pulumi.Input[_builtins.str]] = None,
                 mount_target_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ExportSetArgs.__new__(ExportSetArgs)

            __props__.__dict__["display_name"] = display_name
            __props__.__dict__["max_fs_stat_bytes"] = max_fs_stat_bytes
            __props__.__dict__["max_fs_stat_files"] = max_fs_stat_files
            if mount_target_id is None and not opts.urn:
                raise TypeError("Missing required property 'mount_target_id'")
            __props__.__dict__["mount_target_id"] = mount_target_id
            __props__.__dict__["availability_domain"] = None
            __props__.__dict__["compartment_id"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["vcn_id"] = None
        super(ExportSet, __self__).__init__(
            'oci:FileStorage/exportSet:ExportSet',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            availability_domain: Optional[pulumi.Input[_builtins.str]] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            display_name: Optional[pulumi.Input[_builtins.str]] = None,
            max_fs_stat_bytes: Optional[pulumi.Input[_builtins.str]] = None,
            max_fs_stat_files: Optional[pulumi.Input[_builtins.str]] = None,
            mount_target_id: Optional[pulumi.Input[_builtins.str]] = None,
            state: Optional[pulumi.Input[_builtins.str]] = None,
            time_created: Optional[pulumi.Input[_builtins.str]] = None,
            vcn_id: Optional[pulumi.Input[_builtins.str]] = None) -> 'ExportSet':
        """
        Get an existing ExportSet resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] availability_domain: The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
        :param pulumi.Input[_builtins.str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
        :param pulumi.Input[_builtins.str] display_name: (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
        :param pulumi.Input[_builtins.str] max_fs_stat_bytes: (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
        :param pulumi.Input[_builtins.str] max_fs_stat_files: (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'. 
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] mount_target_id: (Updatable) The OCID of the mount target that the export set is associated with
        :param pulumi.Input[_builtins.str] state: The current state of the export set.
        :param pulumi.Input[_builtins.str] time_created: The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        :param pulumi.Input[_builtins.str] vcn_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ExportSetState.__new__(_ExportSetState)

        __props__.__dict__["availability_domain"] = availability_domain
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["max_fs_stat_bytes"] = max_fs_stat_bytes
        __props__.__dict__["max_fs_stat_files"] = max_fs_stat_files
        __props__.__dict__["mount_target_id"] = mount_target_id
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["vcn_id"] = vcn_id
        return ExportSet(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> pulumi.Output[_builtins.str]:
        """
        The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="maxFsStatBytes")
    def max_fs_stat_bytes(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
        """
        return pulumi.get(self, "max_fs_stat_bytes")

    @_builtins.property
    @pulumi.getter(name="maxFsStatFiles")
    def max_fs_stat_files(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'. 

        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "max_fs_stat_files")

    @_builtins.property
    @pulumi.getter(name="mountTargetId")
    def mount_target_id(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) The OCID of the mount target that the export set is associated with
        """
        return pulumi.get(self, "mount_target_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> pulumi.Output[_builtins.str]:
        """
        The current state of the export set.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[_builtins.str]:
        """
        The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
        """
        return pulumi.get(self, "vcn_id")

