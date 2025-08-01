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
    'GetJavaReleaseResult',
    'AwaitableGetJavaReleaseResult',
    'get_java_release',
    'get_java_release_output',
]

@pulumi.output_type
class GetJavaReleaseResult:
    """
    A collection of values returned by getJavaRelease.
    """
    def __init__(__self__, artifact_content_types=None, artifacts=None, days_under_security_baseline=None, family_details=None, family_version=None, id=None, license_details=None, license_type=None, mos_patches=None, parent_release_version=None, release_date=None, release_notes_url=None, release_type=None, release_version=None, security_status=None):
        if artifact_content_types and not isinstance(artifact_content_types, list):
            raise TypeError("Expected argument 'artifact_content_types' to be a list")
        pulumi.set(__self__, "artifact_content_types", artifact_content_types)
        if artifacts and not isinstance(artifacts, list):
            raise TypeError("Expected argument 'artifacts' to be a list")
        pulumi.set(__self__, "artifacts", artifacts)
        if days_under_security_baseline and not isinstance(days_under_security_baseline, int):
            raise TypeError("Expected argument 'days_under_security_baseline' to be a int")
        pulumi.set(__self__, "days_under_security_baseline", days_under_security_baseline)
        if family_details and not isinstance(family_details, list):
            raise TypeError("Expected argument 'family_details' to be a list")
        pulumi.set(__self__, "family_details", family_details)
        if family_version and not isinstance(family_version, str):
            raise TypeError("Expected argument 'family_version' to be a str")
        pulumi.set(__self__, "family_version", family_version)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if license_details and not isinstance(license_details, list):
            raise TypeError("Expected argument 'license_details' to be a list")
        pulumi.set(__self__, "license_details", license_details)
        if license_type and not isinstance(license_type, str):
            raise TypeError("Expected argument 'license_type' to be a str")
        pulumi.set(__self__, "license_type", license_type)
        if mos_patches and not isinstance(mos_patches, list):
            raise TypeError("Expected argument 'mos_patches' to be a list")
        pulumi.set(__self__, "mos_patches", mos_patches)
        if parent_release_version and not isinstance(parent_release_version, str):
            raise TypeError("Expected argument 'parent_release_version' to be a str")
        pulumi.set(__self__, "parent_release_version", parent_release_version)
        if release_date and not isinstance(release_date, str):
            raise TypeError("Expected argument 'release_date' to be a str")
        pulumi.set(__self__, "release_date", release_date)
        if release_notes_url and not isinstance(release_notes_url, str):
            raise TypeError("Expected argument 'release_notes_url' to be a str")
        pulumi.set(__self__, "release_notes_url", release_notes_url)
        if release_type and not isinstance(release_type, str):
            raise TypeError("Expected argument 'release_type' to be a str")
        pulumi.set(__self__, "release_type", release_type)
        if release_version and not isinstance(release_version, str):
            raise TypeError("Expected argument 'release_version' to be a str")
        pulumi.set(__self__, "release_version", release_version)
        if security_status and not isinstance(security_status, str):
            raise TypeError("Expected argument 'security_status' to be a str")
        pulumi.set(__self__, "security_status", security_status)

    @_builtins.property
    @pulumi.getter(name="artifactContentTypes")
    def artifact_content_types(self) -> Sequence[_builtins.str]:
        """
        Artifact content types for the Java version.
        """
        return pulumi.get(self, "artifact_content_types")

    @_builtins.property
    @pulumi.getter
    def artifacts(self) -> Sequence['outputs.GetJavaReleaseArtifactResult']:
        """
        List of Java artifacts.
        """
        return pulumi.get(self, "artifacts")

    @_builtins.property
    @pulumi.getter(name="daysUnderSecurityBaseline")
    def days_under_security_baseline(self) -> _builtins.int:
        """
        The number of days since this release has been under the security baseline.
        """
        return pulumi.get(self, "days_under_security_baseline")

    @_builtins.property
    @pulumi.getter(name="familyDetails")
    def family_details(self) -> Sequence['outputs.GetJavaReleaseFamilyDetailResult']:
        """
        Metadata associated with a specific Java release family. A Java release family is typically a major version in the Java version identifier.
        """
        return pulumi.get(self, "family_details")

    @_builtins.property
    @pulumi.getter(name="familyVersion")
    def family_version(self) -> _builtins.str:
        """
        Java release family identifier.
        """
        return pulumi.get(self, "family_version")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="licenseDetails")
    def license_details(self) -> Sequence['outputs.GetJavaReleaseLicenseDetailResult']:
        """
        Information about a license type for Java.
        """
        return pulumi.get(self, "license_details")

    @_builtins.property
    @pulumi.getter(name="licenseType")
    def license_type(self) -> _builtins.str:
        """
        License type for the Java version.
        """
        return pulumi.get(self, "license_type")

    @_builtins.property
    @pulumi.getter(name="mosPatches")
    def mos_patches(self) -> Sequence['outputs.GetJavaReleaseMosPatchResult']:
        """
        List of My Oracle Support(MoS) patches available for this release. This information is only available for `BPR` release type.
        """
        return pulumi.get(self, "mos_patches")

    @_builtins.property
    @pulumi.getter(name="parentReleaseVersion")
    def parent_release_version(self) -> _builtins.str:
        """
        Parent Java release version identifier. This is applicable for BPR releases.
        """
        return pulumi.get(self, "parent_release_version")

    @_builtins.property
    @pulumi.getter(name="releaseDate")
    def release_date(self) -> _builtins.str:
        """
        The release date of the Java version (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        """
        return pulumi.get(self, "release_date")

    @_builtins.property
    @pulumi.getter(name="releaseNotesUrl")
    def release_notes_url(self) -> _builtins.str:
        """
        Release notes associated with the Java version.
        """
        return pulumi.get(self, "release_notes_url")

    @_builtins.property
    @pulumi.getter(name="releaseType")
    def release_type(self) -> _builtins.str:
        """
        Release category of the Java version.
        """
        return pulumi.get(self, "release_type")

    @_builtins.property
    @pulumi.getter(name="releaseVersion")
    def release_version(self) -> _builtins.str:
        """
        Java release version identifier.
        """
        return pulumi.get(self, "release_version")

    @_builtins.property
    @pulumi.getter(name="securityStatus")
    def security_status(self) -> _builtins.str:
        """
        The security status of the Java version.
        """
        return pulumi.get(self, "security_status")


class AwaitableGetJavaReleaseResult(GetJavaReleaseResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetJavaReleaseResult(
            artifact_content_types=self.artifact_content_types,
            artifacts=self.artifacts,
            days_under_security_baseline=self.days_under_security_baseline,
            family_details=self.family_details,
            family_version=self.family_version,
            id=self.id,
            license_details=self.license_details,
            license_type=self.license_type,
            mos_patches=self.mos_patches,
            parent_release_version=self.parent_release_version,
            release_date=self.release_date,
            release_notes_url=self.release_notes_url,
            release_type=self.release_type,
            release_version=self.release_version,
            security_status=self.security_status)


def get_java_release(release_version: Optional[_builtins.str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetJavaReleaseResult:
    """
    This data source provides details about a specific Java Release resource in Oracle Cloud Infrastructure Jms service.

    Returns detail of a Java release.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_java_release = oci.Jms.get_java_release(release_version=java_release_release_version)
    ```


    :param _builtins.str release_version: Unique Java release version identifier
    """
    __args__ = dict()
    __args__['releaseVersion'] = release_version
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Jms/getJavaRelease:getJavaRelease', __args__, opts=opts, typ=GetJavaReleaseResult).value

    return AwaitableGetJavaReleaseResult(
        artifact_content_types=pulumi.get(__ret__, 'artifact_content_types'),
        artifacts=pulumi.get(__ret__, 'artifacts'),
        days_under_security_baseline=pulumi.get(__ret__, 'days_under_security_baseline'),
        family_details=pulumi.get(__ret__, 'family_details'),
        family_version=pulumi.get(__ret__, 'family_version'),
        id=pulumi.get(__ret__, 'id'),
        license_details=pulumi.get(__ret__, 'license_details'),
        license_type=pulumi.get(__ret__, 'license_type'),
        mos_patches=pulumi.get(__ret__, 'mos_patches'),
        parent_release_version=pulumi.get(__ret__, 'parent_release_version'),
        release_date=pulumi.get(__ret__, 'release_date'),
        release_notes_url=pulumi.get(__ret__, 'release_notes_url'),
        release_type=pulumi.get(__ret__, 'release_type'),
        release_version=pulumi.get(__ret__, 'release_version'),
        security_status=pulumi.get(__ret__, 'security_status'))
def get_java_release_output(release_version: Optional[pulumi.Input[_builtins.str]] = None,
                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetJavaReleaseResult]:
    """
    This data source provides details about a specific Java Release resource in Oracle Cloud Infrastructure Jms service.

    Returns detail of a Java release.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_java_release = oci.Jms.get_java_release(release_version=java_release_release_version)
    ```


    :param _builtins.str release_version: Unique Java release version identifier
    """
    __args__ = dict()
    __args__['releaseVersion'] = release_version
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Jms/getJavaRelease:getJavaRelease', __args__, opts=opts, typ=GetJavaReleaseResult)
    return __ret__.apply(lambda __response__: GetJavaReleaseResult(
        artifact_content_types=pulumi.get(__response__, 'artifact_content_types'),
        artifacts=pulumi.get(__response__, 'artifacts'),
        days_under_security_baseline=pulumi.get(__response__, 'days_under_security_baseline'),
        family_details=pulumi.get(__response__, 'family_details'),
        family_version=pulumi.get(__response__, 'family_version'),
        id=pulumi.get(__response__, 'id'),
        license_details=pulumi.get(__response__, 'license_details'),
        license_type=pulumi.get(__response__, 'license_type'),
        mos_patches=pulumi.get(__response__, 'mos_patches'),
        parent_release_version=pulumi.get(__response__, 'parent_release_version'),
        release_date=pulumi.get(__response__, 'release_date'),
        release_notes_url=pulumi.get(__response__, 'release_notes_url'),
        release_type=pulumi.get(__response__, 'release_type'),
        release_version=pulumi.get(__response__, 'release_version'),
        security_status=pulumi.get(__response__, 'security_status')))
