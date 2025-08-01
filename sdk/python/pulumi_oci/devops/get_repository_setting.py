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

__all__ = [
    'GetRepositorySettingResult',
    'AwaitableGetRepositorySettingResult',
    'get_repository_setting',
    'get_repository_setting_output',
]

@pulumi.output_type
class GetRepositorySettingResult:
    """
    A collection of values returned by getRepositorySetting.
    """
    def __init__(__self__, approval_rules=None, id=None, merge_checks=None, merge_settings=None, repository_id=None):
        if approval_rules and not isinstance(approval_rules, list):
            raise TypeError("Expected argument 'approval_rules' to be a list")
        pulumi.set(__self__, "approval_rules", approval_rules)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if merge_checks and not isinstance(merge_checks, list):
            raise TypeError("Expected argument 'merge_checks' to be a list")
        pulumi.set(__self__, "merge_checks", merge_checks)
        if merge_settings and not isinstance(merge_settings, list):
            raise TypeError("Expected argument 'merge_settings' to be a list")
        pulumi.set(__self__, "merge_settings", merge_settings)
        if repository_id and not isinstance(repository_id, str):
            raise TypeError("Expected argument 'repository_id' to be a str")
        pulumi.set(__self__, "repository_id", repository_id)

    @_builtins.property
    @pulumi.getter(name="approvalRules")
    def approval_rules(self) -> Sequence['outputs.GetRepositorySettingApprovalRuleResult']:
        """
        List of approval rules which must be statisfied before pull requests which match the rules can be merged
        """
        return pulumi.get(self, "approval_rules")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="mergeChecks")
    def merge_checks(self) -> Sequence['outputs.GetRepositorySettingMergeCheckResult']:
        """
        Criteria which must be satisfied to merge a pull request.
        """
        return pulumi.get(self, "merge_checks")

    @_builtins.property
    @pulumi.getter(name="mergeSettings")
    def merge_settings(self) -> Sequence['outputs.GetRepositorySettingMergeSettingResult']:
        """
        Enabled and disabled merge strategies for a project or repository, also contains a default strategy.
        """
        return pulumi.get(self, "merge_settings")

    @_builtins.property
    @pulumi.getter(name="repositoryId")
    def repository_id(self) -> _builtins.str:
        return pulumi.get(self, "repository_id")


class AwaitableGetRepositorySettingResult(GetRepositorySettingResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRepositorySettingResult(
            approval_rules=self.approval_rules,
            id=self.id,
            merge_checks=self.merge_checks,
            merge_settings=self.merge_settings,
            repository_id=self.repository_id)


def get_repository_setting(repository_id: Optional[_builtins.str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRepositorySettingResult:
    """
    This data source provides details about a specific Repository Setting resource in Oracle Cloud Infrastructure Devops service.

    Retrieves a repository's settings details.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repository_setting = oci.DevOps.get_repository_setting(repository_id=test_repository["id"])
    ```


    :param _builtins.str repository_id: Unique repository identifier.
    """
    __args__ = dict()
    __args__['repositoryId'] = repository_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getRepositorySetting:getRepositorySetting', __args__, opts=opts, typ=GetRepositorySettingResult).value

    return AwaitableGetRepositorySettingResult(
        approval_rules=pulumi.get(__ret__, 'approval_rules'),
        id=pulumi.get(__ret__, 'id'),
        merge_checks=pulumi.get(__ret__, 'merge_checks'),
        merge_settings=pulumi.get(__ret__, 'merge_settings'),
        repository_id=pulumi.get(__ret__, 'repository_id'))
def get_repository_setting_output(repository_id: Optional[pulumi.Input[_builtins.str]] = None,
                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetRepositorySettingResult]:
    """
    This data source provides details about a specific Repository Setting resource in Oracle Cloud Infrastructure Devops service.

    Retrieves a repository's settings details.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_repository_setting = oci.DevOps.get_repository_setting(repository_id=test_repository["id"])
    ```


    :param _builtins.str repository_id: Unique repository identifier.
    """
    __args__ = dict()
    __args__['repositoryId'] = repository_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DevOps/getRepositorySetting:getRepositorySetting', __args__, opts=opts, typ=GetRepositorySettingResult)
    return __ret__.apply(lambda __response__: GetRepositorySettingResult(
        approval_rules=pulumi.get(__response__, 'approval_rules'),
        id=pulumi.get(__response__, 'id'),
        merge_checks=pulumi.get(__response__, 'merge_checks'),
        merge_settings=pulumi.get(__response__, 'merge_settings'),
        repository_id=pulumi.get(__response__, 'repository_id')))
