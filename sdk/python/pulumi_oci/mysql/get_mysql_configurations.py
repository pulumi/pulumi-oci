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

__all__ = [
    'GetMysqlConfigurationsResult',
    'AwaitableGetMysqlConfigurationsResult',
    'get_mysql_configurations',
    'get_mysql_configurations_output',
]

@pulumi.output_type
class GetMysqlConfigurationsResult:
    """
    A collection of values returned by getMysqlConfigurations.
    """
    def __init__(__self__, compartment_id=None, configuration_id=None, configurations=None, display_name=None, filters=None, id=None, shape_name=None, state=None, types=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if configuration_id and not isinstance(configuration_id, str):
            raise TypeError("Expected argument 'configuration_id' to be a str")
        pulumi.set(__self__, "configuration_id", configuration_id)
        if configurations and not isinstance(configurations, list):
            raise TypeError("Expected argument 'configurations' to be a list")
        pulumi.set(__self__, "configurations", configurations)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if shape_name and not isinstance(shape_name, str):
            raise TypeError("Expected argument 'shape_name' to be a str")
        pulumi.set(__self__, "shape_name", shape_name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if types and not isinstance(types, list):
            raise TypeError("Expected argument 'types' to be a list")
        pulumi.set(__self__, "types", types)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        OCID of the Compartment the Configuration exists in.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="configurationId")
    def configuration_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "configuration_id")

    @_builtins.property
    @pulumi.getter
    def configurations(self) -> Sequence['outputs.GetMysqlConfigurationsConfigurationResult']:
        """
        The list of configurations.
        """
        return pulumi.get(self, "configurations")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The display name of the Configuration.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetMysqlConfigurationsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="shapeName")
    def shape_name(self) -> Optional[_builtins.str]:
        """
        The name of the associated Shape.
        """
        return pulumi.get(self, "shape_name")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the Configuration.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter
    def types(self) -> Optional[Sequence[_builtins.str]]:
        """
        The Configuration type, DEFAULT or CUSTOM.
        """
        return pulumi.get(self, "types")


class AwaitableGetMysqlConfigurationsResult(GetMysqlConfigurationsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMysqlConfigurationsResult(
            compartment_id=self.compartment_id,
            configuration_id=self.configuration_id,
            configurations=self.configurations,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            shape_name=self.shape_name,
            state=self.state,
            types=self.types)


def get_mysql_configurations(compartment_id: Optional[_builtins.str] = None,
                             configuration_id: Optional[_builtins.str] = None,
                             display_name: Optional[_builtins.str] = None,
                             filters: Optional[Sequence[Union['GetMysqlConfigurationsFilterArgs', 'GetMysqlConfigurationsFilterArgsDict']]] = None,
                             shape_name: Optional[_builtins.str] = None,
                             state: Optional[_builtins.str] = None,
                             types: Optional[Sequence[_builtins.str]] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMysqlConfigurationsResult:
    """
    This data source provides the list of Mysql Configurations in Oracle Cloud Infrastructure MySQL Database service.

    Lists the Configurations available when creating a DB System.

    This may include DEFAULT configurations per Shape and CUSTOM configurations.

    The default sort order is a multi-part sort by:
      - shapeName, ascending
      - DEFAULT-before-CUSTOM
      - displayName ascending

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_mysql_configurations = oci.Mysql.get_mysql_configurations(compartment_id=compartment_id,
        configuration_id=mysql_configuration_id,
        display_name=mysql_configuration_display_name,
        shape_name=mysql_shape_name,
        state=mysql_configuration_state,
        types=mysql_configuration_type)
    ```


    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str configuration_id: The requested Configuration instance.
    :param _builtins.str display_name: A filter to return only the resource matching the given display name exactly.
    :param _builtins.str shape_name: The requested Shape name.
    :param _builtins.str state: Configuration Lifecycle State
    :param Sequence[_builtins.str] types: The requested Configuration types.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['configurationId'] = configuration_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['shapeName'] = shape_name
    __args__['state'] = state
    __args__['types'] = types
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Mysql/getMysqlConfigurations:getMysqlConfigurations', __args__, opts=opts, typ=GetMysqlConfigurationsResult).value

    return AwaitableGetMysqlConfigurationsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        configuration_id=pulumi.get(__ret__, 'configuration_id'),
        configurations=pulumi.get(__ret__, 'configurations'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        shape_name=pulumi.get(__ret__, 'shape_name'),
        state=pulumi.get(__ret__, 'state'),
        types=pulumi.get(__ret__, 'types'))
def get_mysql_configurations_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                    configuration_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                    display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                    filters: Optional[pulumi.Input[Optional[Sequence[Union['GetMysqlConfigurationsFilterArgs', 'GetMysqlConfigurationsFilterArgsDict']]]]] = None,
                                    shape_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                    state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                    types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetMysqlConfigurationsResult]:
    """
    This data source provides the list of Mysql Configurations in Oracle Cloud Infrastructure MySQL Database service.

    Lists the Configurations available when creating a DB System.

    This may include DEFAULT configurations per Shape and CUSTOM configurations.

    The default sort order is a multi-part sort by:
      - shapeName, ascending
      - DEFAULT-before-CUSTOM
      - displayName ascending

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_mysql_configurations = oci.Mysql.get_mysql_configurations(compartment_id=compartment_id,
        configuration_id=mysql_configuration_id,
        display_name=mysql_configuration_display_name,
        shape_name=mysql_shape_name,
        state=mysql_configuration_state,
        types=mysql_configuration_type)
    ```


    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str configuration_id: The requested Configuration instance.
    :param _builtins.str display_name: A filter to return only the resource matching the given display name exactly.
    :param _builtins.str shape_name: The requested Shape name.
    :param _builtins.str state: Configuration Lifecycle State
    :param Sequence[_builtins.str] types: The requested Configuration types.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['configurationId'] = configuration_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['shapeName'] = shape_name
    __args__['state'] = state
    __args__['types'] = types
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Mysql/getMysqlConfigurations:getMysqlConfigurations', __args__, opts=opts, typ=GetMysqlConfigurationsResult)
    return __ret__.apply(lambda __response__: GetMysqlConfigurationsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        configuration_id=pulumi.get(__response__, 'configuration_id'),
        configurations=pulumi.get(__response__, 'configurations'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        shape_name=pulumi.get(__response__, 'shape_name'),
        state=pulumi.get(__response__, 'state'),
        types=pulumi.get(__response__, 'types')))
