// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package aivision

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Model resource in Oracle Cloud Infrastructure Ai Vision service.
//
// # Gets a Model by identifier
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/AiVision"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := AiVision.GetModel(ctx, &aivision.GetModelArgs{
//				ModelId: oci_ai_vision_model.Test_model.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupModel(ctx *pulumi.Context, args *LookupModelArgs, opts ...pulumi.InvokeOption) (*LookupModelResult, error) {
	var rv LookupModelResult
	err := ctx.Invoke("oci:AiVision/getModel:getModel", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getModel.
type LookupModelArgs struct {
	// unique Model identifier
	ModelId string `pulumi:"modelId"`
}

// A collection of values returned by getModel.
type LookupModelResult struct {
	// Average precision of the trained model
	AveragePrecision float64 `pulumi:"averagePrecision"`
	// Compartment Identifier
	CompartmentId string `pulumi:"compartmentId"`
	// Confidence ratio of the calculation
	ConfidenceThreshold float64 `pulumi:"confidenceThreshold"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A short description of the model.
	Description string `pulumi:"description"`
	// Model Identifier, can be renamed
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Unique identifier that is immutable on creation
	Id string `pulumi:"id"`
	// If It's true, Training is set for recommended epochs needed for quick training.
	IsQuickMode bool `pulumi:"isQuickMode"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The maximum duration in hours for which the training will run.
	MaxTrainingDurationInHours float64 `pulumi:"maxTrainingDurationInHours"`
	// Complete Training Metrics for successful trained model
	Metrics string `pulumi:"metrics"`
	ModelId string `pulumi:"modelId"`
	// Type of the Model.
	ModelType string `pulumi:"modelType"`
	// The version of the model
	ModelVersion string `pulumi:"modelVersion"`
	// Precision of the trained model
	Precision float64 `pulumi:"precision"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
	ProjectId string `pulumi:"projectId"`
	// Recall of the trained model
	Recall float64 `pulumi:"recall"`
	// The current state of the Model.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// Total number of testing Images
	TestImageCount int `pulumi:"testImageCount"`
	// The base entity for a Dataset, which is the input for Model creation.
	TestingDatasets []GetModelTestingDataset `pulumi:"testingDatasets"`
	// The time the Model was created. An RFC3339 formatted datetime string
	TimeCreated string `pulumi:"timeCreated"`
	// The time the Model was updated. An RFC3339 formatted datetime string
	TimeUpdated string `pulumi:"timeUpdated"`
	// Total number of training Images
	TotalImageCount int `pulumi:"totalImageCount"`
	// Total hours actually used for training
	TrainedDurationInHours float64 `pulumi:"trainedDurationInHours"`
	// The base entity for a Dataset, which is the input for Model creation.
	TrainingDatasets []GetModelTrainingDataset `pulumi:"trainingDatasets"`
	// The base entity for a Dataset, which is the input for Model creation.
	ValidationDatasets []GetModelValidationDataset `pulumi:"validationDatasets"`
}

func LookupModelOutput(ctx *pulumi.Context, args LookupModelOutputArgs, opts ...pulumi.InvokeOption) LookupModelResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupModelResult, error) {
			args := v.(LookupModelArgs)
			r, err := LookupModel(ctx, &args, opts...)
			var s LookupModelResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupModelResultOutput)
}

// A collection of arguments for invoking getModel.
type LookupModelOutputArgs struct {
	// unique Model identifier
	ModelId pulumi.StringInput `pulumi:"modelId"`
}

func (LookupModelOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupModelArgs)(nil)).Elem()
}

// A collection of values returned by getModel.
type LookupModelResultOutput struct{ *pulumi.OutputState }

func (LookupModelResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupModelResult)(nil)).Elem()
}

func (o LookupModelResultOutput) ToLookupModelResultOutput() LookupModelResultOutput {
	return o
}

func (o LookupModelResultOutput) ToLookupModelResultOutputWithContext(ctx context.Context) LookupModelResultOutput {
	return o
}

// Average precision of the trained model
func (o LookupModelResultOutput) AveragePrecision() pulumi.Float64Output {
	return o.ApplyT(func(v LookupModelResult) float64 { return v.AveragePrecision }).(pulumi.Float64Output)
}

// Compartment Identifier
func (o LookupModelResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Confidence ratio of the calculation
func (o LookupModelResultOutput) ConfidenceThreshold() pulumi.Float64Output {
	return o.ApplyT(func(v LookupModelResult) float64 { return v.ConfidenceThreshold }).(pulumi.Float64Output)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupModelResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupModelResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A short description of the model.
func (o LookupModelResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.Description }).(pulumi.StringOutput)
}

// Model Identifier, can be renamed
func (o LookupModelResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupModelResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupModelResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Unique identifier that is immutable on creation
func (o LookupModelResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.Id }).(pulumi.StringOutput)
}

// If It's true, Training is set for recommended epochs needed for quick training.
func (o LookupModelResultOutput) IsQuickMode() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupModelResult) bool { return v.IsQuickMode }).(pulumi.BoolOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o LookupModelResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The maximum duration in hours for which the training will run.
func (o LookupModelResultOutput) MaxTrainingDurationInHours() pulumi.Float64Output {
	return o.ApplyT(func(v LookupModelResult) float64 { return v.MaxTrainingDurationInHours }).(pulumi.Float64Output)
}

// Complete Training Metrics for successful trained model
func (o LookupModelResultOutput) Metrics() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.Metrics }).(pulumi.StringOutput)
}

func (o LookupModelResultOutput) ModelId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.ModelId }).(pulumi.StringOutput)
}

// Type of the Model.
func (o LookupModelResultOutput) ModelType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.ModelType }).(pulumi.StringOutput)
}

// The version of the model
func (o LookupModelResultOutput) ModelVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.ModelVersion }).(pulumi.StringOutput)
}

// Precision of the trained model
func (o LookupModelResultOutput) Precision() pulumi.Float64Output {
	return o.ApplyT(func(v LookupModelResult) float64 { return v.Precision }).(pulumi.Float64Output)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
func (o LookupModelResultOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.ProjectId }).(pulumi.StringOutput)
}

// Recall of the trained model
func (o LookupModelResultOutput) Recall() pulumi.Float64Output {
	return o.ApplyT(func(v LookupModelResult) float64 { return v.Recall }).(pulumi.Float64Output)
}

// The current state of the Model.
func (o LookupModelResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupModelResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupModelResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// Total number of testing Images
func (o LookupModelResultOutput) TestImageCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupModelResult) int { return v.TestImageCount }).(pulumi.IntOutput)
}

// The base entity for a Dataset, which is the input for Model creation.
func (o LookupModelResultOutput) TestingDatasets() GetModelTestingDatasetArrayOutput {
	return o.ApplyT(func(v LookupModelResult) []GetModelTestingDataset { return v.TestingDatasets }).(GetModelTestingDatasetArrayOutput)
}

// The time the Model was created. An RFC3339 formatted datetime string
func (o LookupModelResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the Model was updated. An RFC3339 formatted datetime string
func (o LookupModelResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupModelResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Total number of training Images
func (o LookupModelResultOutput) TotalImageCount() pulumi.IntOutput {
	return o.ApplyT(func(v LookupModelResult) int { return v.TotalImageCount }).(pulumi.IntOutput)
}

// Total hours actually used for training
func (o LookupModelResultOutput) TrainedDurationInHours() pulumi.Float64Output {
	return o.ApplyT(func(v LookupModelResult) float64 { return v.TrainedDurationInHours }).(pulumi.Float64Output)
}

// The base entity for a Dataset, which is the input for Model creation.
func (o LookupModelResultOutput) TrainingDatasets() GetModelTrainingDatasetArrayOutput {
	return o.ApplyT(func(v LookupModelResult) []GetModelTrainingDataset { return v.TrainingDatasets }).(GetModelTrainingDatasetArrayOutput)
}

// The base entity for a Dataset, which is the input for Model creation.
func (o LookupModelResultOutput) ValidationDatasets() GetModelValidationDatasetArrayOutput {
	return o.ApplyT(func(v LookupModelResult) []GetModelValidationDataset { return v.ValidationDatasets }).(GetModelValidationDatasetArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupModelResultOutput{})
}