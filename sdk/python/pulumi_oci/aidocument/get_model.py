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

__all__ = [
    'GetModelResult',
    'AwaitableGetModelResult',
    'get_model',
    'get_model_output',
]

@pulumi.output_type
class GetModelResult:
    """
    A collection of values returned by getModel.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, is_quick_mode=None, labels=None, lifecycle_details=None, max_training_time_in_hours=None, metrics=None, model_id=None, model_type=None, model_version=None, project_id=None, state=None, system_tags=None, testing_datasets=None, time_created=None, time_updated=None, trained_time_in_hours=None, training_datasets=None, validation_datasets=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_quick_mode and not isinstance(is_quick_mode, bool):
            raise TypeError("Expected argument 'is_quick_mode' to be a bool")
        pulumi.set(__self__, "is_quick_mode", is_quick_mode)
        if labels and not isinstance(labels, list):
            raise TypeError("Expected argument 'labels' to be a list")
        pulumi.set(__self__, "labels", labels)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if max_training_time_in_hours and not isinstance(max_training_time_in_hours, float):
            raise TypeError("Expected argument 'max_training_time_in_hours' to be a float")
        pulumi.set(__self__, "max_training_time_in_hours", max_training_time_in_hours)
        if metrics and not isinstance(metrics, list):
            raise TypeError("Expected argument 'metrics' to be a list")
        pulumi.set(__self__, "metrics", metrics)
        if model_id and not isinstance(model_id, str):
            raise TypeError("Expected argument 'model_id' to be a str")
        pulumi.set(__self__, "model_id", model_id)
        if model_type and not isinstance(model_type, str):
            raise TypeError("Expected argument 'model_type' to be a str")
        pulumi.set(__self__, "model_type", model_type)
        if model_version and not isinstance(model_version, str):
            raise TypeError("Expected argument 'model_version' to be a str")
        pulumi.set(__self__, "model_version", model_version)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if testing_datasets and not isinstance(testing_datasets, list):
            raise TypeError("Expected argument 'testing_datasets' to be a list")
        pulumi.set(__self__, "testing_datasets", testing_datasets)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if trained_time_in_hours and not isinstance(trained_time_in_hours, float):
            raise TypeError("Expected argument 'trained_time_in_hours' to be a float")
        pulumi.set(__self__, "trained_time_in_hours", trained_time_in_hours)
        if training_datasets and not isinstance(training_datasets, list):
            raise TypeError("Expected argument 'training_datasets' to be a list")
        pulumi.set(__self__, "training_datasets", training_datasets)
        if validation_datasets and not isinstance(validation_datasets, list):
            raise TypeError("Expected argument 'validation_datasets' to be a list")
        pulumi.set(__self__, "validation_datasets", validation_datasets)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The compartment identifier.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For example: `{"foo-namespace": {"bar-key": "value"}}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        An optional description of the model.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A human-friendly name for the model, which can be changed.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        A simple key-value pair that is applied without any predefined name, type, or scope. It exists for cross-compatibility only. For example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        A unique identifier that is immutable after creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isQuickMode")
    def is_quick_mode(self) -> bool:
        """
        Set to true when experimenting with a new model type or dataset, so model training is quick, with a predefined low number of passes through the training data.
        """
        return pulumi.get(self, "is_quick_mode")

    @property
    @pulumi.getter
    def labels(self) -> Sequence[str]:
        """
        The collection of labels used to train the custom model.
        """
        return pulumi.get(self, "labels")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail, that can provide actionable information if training failed.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="maxTrainingTimeInHours")
    def max_training_time_in_hours(self) -> float:
        """
        The maximum model training time in hours, expressed as a decimal fraction.
        """
        return pulumi.get(self, "max_training_time_in_hours")

    @property
    @pulumi.getter
    def metrics(self) -> Sequence['outputs.GetModelMetricResult']:
        """
        Trained Model Metrics.
        """
        return pulumi.get(self, "metrics")

    @property
    @pulumi.getter(name="modelId")
    def model_id(self) -> str:
        return pulumi.get(self, "model_id")

    @property
    @pulumi.getter(name="modelType")
    def model_type(self) -> str:
        """
        The type of the Document model.
        """
        return pulumi.get(self, "model_type")

    @property
    @pulumi.getter(name="modelVersion")
    def model_version(self) -> str:
        """
        The version of the model.
        """
        return pulumi.get(self, "model_version")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project that contains the model.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the model.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. For example: `{"orcl-cloud": {"free-tier-retained": "true"}}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="testingDatasets")
    def testing_datasets(self) -> Sequence['outputs.GetModelTestingDatasetResult']:
        """
        The base entity which is the input for creating and training a model.
        """
        return pulumi.get(self, "testing_datasets")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        When the model was created, as an RFC3339 datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        When the model was updated, as an RFC3339 datetime string.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="trainedTimeInHours")
    def trained_time_in_hours(self) -> float:
        """
        The total hours actually used for model training.
        """
        return pulumi.get(self, "trained_time_in_hours")

    @property
    @pulumi.getter(name="trainingDatasets")
    def training_datasets(self) -> Sequence['outputs.GetModelTrainingDatasetResult']:
        """
        The base entity which is the input for creating and training a model.
        """
        return pulumi.get(self, "training_datasets")

    @property
    @pulumi.getter(name="validationDatasets")
    def validation_datasets(self) -> Sequence['outputs.GetModelValidationDatasetResult']:
        """
        The base entity which is the input for creating and training a model.
        """
        return pulumi.get(self, "validation_datasets")


class AwaitableGetModelResult(GetModelResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetModelResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_quick_mode=self.is_quick_mode,
            labels=self.labels,
            lifecycle_details=self.lifecycle_details,
            max_training_time_in_hours=self.max_training_time_in_hours,
            metrics=self.metrics,
            model_id=self.model_id,
            model_type=self.model_type,
            model_version=self.model_version,
            project_id=self.project_id,
            state=self.state,
            system_tags=self.system_tags,
            testing_datasets=self.testing_datasets,
            time_created=self.time_created,
            time_updated=self.time_updated,
            trained_time_in_hours=self.trained_time_in_hours,
            training_datasets=self.training_datasets,
            validation_datasets=self.validation_datasets)


def get_model(model_id: Optional[str] = None,
              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetModelResult:
    """
    This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Document service.

    Get a model by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_model = oci.AiDocument.get_model(model_id=oci_ai_document_model["test_model"]["id"])
    ```


    :param str model_id: A unique model identifier.
    """
    __args__ = dict()
    __args__['modelId'] = model_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:AiDocument/getModel:getModel', __args__, opts=opts, typ=GetModelResult).value

    return AwaitableGetModelResult(
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        description=__ret__.description,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        is_quick_mode=__ret__.is_quick_mode,
        labels=__ret__.labels,
        lifecycle_details=__ret__.lifecycle_details,
        max_training_time_in_hours=__ret__.max_training_time_in_hours,
        metrics=__ret__.metrics,
        model_id=__ret__.model_id,
        model_type=__ret__.model_type,
        model_version=__ret__.model_version,
        project_id=__ret__.project_id,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        testing_datasets=__ret__.testing_datasets,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated,
        trained_time_in_hours=__ret__.trained_time_in_hours,
        training_datasets=__ret__.training_datasets,
        validation_datasets=__ret__.validation_datasets)


@_utilities.lift_output_func(get_model)
def get_model_output(model_id: Optional[pulumi.Input[str]] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetModelResult]:
    """
    This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Document service.

    Get a model by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_model = oci.AiDocument.get_model(model_id=oci_ai_document_model["test_model"]["id"])
    ```


    :param str model_id: A unique model identifier.
    """
    ...