# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'FleetInventoryLogArgs',
    'FleetOperationLogArgs',
    'GetFleetBlocklistsFilterArgs',
    'GetFleetsFilterArgs',
    'GetInstallationSitesFilterArgs',
]

@pulumi.input_type
class FleetInventoryLogArgs:
    def __init__(__self__, *,
                 log_group_id: pulumi.Input[str],
                 log_id: pulumi.Input[str]):
        """
        :param pulumi.Input[str] log_group_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
        :param pulumi.Input[str] log_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
        """
        pulumi.set(__self__, "log_group_id", log_group_id)
        pulumi.set(__self__, "log_id", log_id)

    @property
    @pulumi.getter(name="logGroupId")
    def log_group_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
        """
        return pulumi.get(self, "log_group_id")

    @log_group_id.setter
    def log_group_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "log_group_id", value)

    @property
    @pulumi.getter(name="logId")
    def log_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
        """
        return pulumi.get(self, "log_id")

    @log_id.setter
    def log_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "log_id", value)


@pulumi.input_type
class FleetOperationLogArgs:
    def __init__(__self__, *,
                 log_group_id: pulumi.Input[str],
                 log_id: pulumi.Input[str]):
        """
        :param pulumi.Input[str] log_group_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
        :param pulumi.Input[str] log_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
        """
        pulumi.set(__self__, "log_group_id", log_group_id)
        pulumi.set(__self__, "log_id", log_id)

    @property
    @pulumi.getter(name="logGroupId")
    def log_group_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
        """
        return pulumi.get(self, "log_group_id")

    @log_group_id.setter
    def log_group_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "log_group_id", value)

    @property
    @pulumi.getter(name="logId")
    def log_id(self) -> pulumi.Input[str]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
        """
        return pulumi.get(self, "log_id")

    @log_id.setter
    def log_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "log_id", value)


@pulumi.input_type
class GetFleetBlocklistsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetFleetsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetInstallationSitesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: The name of the operating system as provided by the Java system property os.name.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the operating system as provided by the Java system property os.name.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


