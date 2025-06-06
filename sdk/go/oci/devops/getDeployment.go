// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure Devops service.
//
// Retrieves a deployment by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/devops"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := devops.GetDeployment(ctx, &devops.GetDeploymentArgs{
//				DeploymentId: testDeploymentOciDevopsDeployment.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDeployment(ctx *pulumi.Context, args *LookupDeploymentArgs, opts ...pulumi.InvokeOption) (*LookupDeploymentResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDeploymentResult
	err := ctx.Invoke("oci:DevOps/getDeployment:getDeployment", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeployment.
type LookupDeploymentArgs struct {
	// Unique deployment identifier.
	DeploymentId string `pulumi:"deploymentId"`
}

// A collection of values returned by getDeployment.
type LookupDeploymentResult struct {
	// The OCID of a compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Specifies the list of artifact override arguments at the time of deployment.
	DeployArtifactOverrideArguments []GetDeploymentDeployArtifactOverrideArgument `pulumi:"deployArtifactOverrideArguments"`
	// List of all artifacts used in the pipeline.
	DeployPipelineArtifacts []GetDeploymentDeployPipelineArtifact `pulumi:"deployPipelineArtifacts"`
	// List of all environments used in the pipeline.
	DeployPipelineEnvironments []GetDeploymentDeployPipelineEnvironment `pulumi:"deployPipelineEnvironments"`
	// The OCID of a pipeline.
	DeployPipelineId string `pulumi:"deployPipelineId"`
	// The OCID of the stage.
	DeployStageId string `pulumi:"deployStageId"`
	// Specifies the list of arguments to be overriden per Stage at the time of deployment.
	DeployStageOverrideArguments []GetDeploymentDeployStageOverrideArgument `pulumi:"deployStageOverrideArguments"`
	// Specifies list of arguments passed along with the deployment.
	DeploymentArguments []GetDeploymentDeploymentArgument `pulumi:"deploymentArguments"`
	// The execution progress details of a deployment.
	DeploymentExecutionProgresses []GetDeploymentDeploymentExecutionProgress `pulumi:"deploymentExecutionProgresses"`
	DeploymentId                  string                                     `pulumi:"deploymentId"`
	// Specifies type of Deployment
	DeploymentType string `pulumi:"deploymentType"`
	// Deployment identifier which can be renamed and is not necessarily unique. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Unique identifier that is immutable on creation.
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Specifies the OCID of the previous deployment to be redeployed.
	PreviousDeploymentId string `pulumi:"previousDeploymentId"`
	// The OCID of a project.
	ProjectId string `pulumi:"projectId"`
	// The current state of the deployment.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated string `pulumi:"timeCreated"`
	// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated                string `pulumi:"timeUpdated"`
	TriggerNewDevopsDeployment bool   `pulumi:"triggerNewDevopsDeployment"`
}

func LookupDeploymentOutput(ctx *pulumi.Context, args LookupDeploymentOutputArgs, opts ...pulumi.InvokeOption) LookupDeploymentResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDeploymentResultOutput, error) {
			args := v.(LookupDeploymentArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DevOps/getDeployment:getDeployment", args, LookupDeploymentResultOutput{}, options).(LookupDeploymentResultOutput), nil
		}).(LookupDeploymentResultOutput)
}

// A collection of arguments for invoking getDeployment.
type LookupDeploymentOutputArgs struct {
	// Unique deployment identifier.
	DeploymentId pulumi.StringInput `pulumi:"deploymentId"`
}

func (LookupDeploymentOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDeploymentArgs)(nil)).Elem()
}

// A collection of values returned by getDeployment.
type LookupDeploymentResultOutput struct{ *pulumi.OutputState }

func (LookupDeploymentResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDeploymentResult)(nil)).Elem()
}

func (o LookupDeploymentResultOutput) ToLookupDeploymentResultOutput() LookupDeploymentResultOutput {
	return o
}

func (o LookupDeploymentResultOutput) ToLookupDeploymentResultOutputWithContext(ctx context.Context) LookupDeploymentResultOutput {
	return o
}

// The OCID of a compartment.
func (o LookupDeploymentResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupDeploymentResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDeploymentResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Specifies the list of artifact override arguments at the time of deployment.
func (o LookupDeploymentResultOutput) DeployArtifactOverrideArguments() GetDeploymentDeployArtifactOverrideArgumentArrayOutput {
	return o.ApplyT(func(v LookupDeploymentResult) []GetDeploymentDeployArtifactOverrideArgument {
		return v.DeployArtifactOverrideArguments
	}).(GetDeploymentDeployArtifactOverrideArgumentArrayOutput)
}

// List of all artifacts used in the pipeline.
func (o LookupDeploymentResultOutput) DeployPipelineArtifacts() GetDeploymentDeployPipelineArtifactArrayOutput {
	return o.ApplyT(func(v LookupDeploymentResult) []GetDeploymentDeployPipelineArtifact { return v.DeployPipelineArtifacts }).(GetDeploymentDeployPipelineArtifactArrayOutput)
}

// List of all environments used in the pipeline.
func (o LookupDeploymentResultOutput) DeployPipelineEnvironments() GetDeploymentDeployPipelineEnvironmentArrayOutput {
	return o.ApplyT(func(v LookupDeploymentResult) []GetDeploymentDeployPipelineEnvironment {
		return v.DeployPipelineEnvironments
	}).(GetDeploymentDeployPipelineEnvironmentArrayOutput)
}

// The OCID of a pipeline.
func (o LookupDeploymentResultOutput) DeployPipelineId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.DeployPipelineId }).(pulumi.StringOutput)
}

// The OCID of the stage.
func (o LookupDeploymentResultOutput) DeployStageId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.DeployStageId }).(pulumi.StringOutput)
}

// Specifies the list of arguments to be overriden per Stage at the time of deployment.
func (o LookupDeploymentResultOutput) DeployStageOverrideArguments() GetDeploymentDeployStageOverrideArgumentArrayOutput {
	return o.ApplyT(func(v LookupDeploymentResult) []GetDeploymentDeployStageOverrideArgument {
		return v.DeployStageOverrideArguments
	}).(GetDeploymentDeployStageOverrideArgumentArrayOutput)
}

// Specifies list of arguments passed along with the deployment.
func (o LookupDeploymentResultOutput) DeploymentArguments() GetDeploymentDeploymentArgumentArrayOutput {
	return o.ApplyT(func(v LookupDeploymentResult) []GetDeploymentDeploymentArgument { return v.DeploymentArguments }).(GetDeploymentDeploymentArgumentArrayOutput)
}

// The execution progress details of a deployment.
func (o LookupDeploymentResultOutput) DeploymentExecutionProgresses() GetDeploymentDeploymentExecutionProgressArrayOutput {
	return o.ApplyT(func(v LookupDeploymentResult) []GetDeploymentDeploymentExecutionProgress {
		return v.DeploymentExecutionProgresses
	}).(GetDeploymentDeploymentExecutionProgressArrayOutput)
}

func (o LookupDeploymentResultOutput) DeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.DeploymentId }).(pulumi.StringOutput)
}

// Specifies type of Deployment
func (o LookupDeploymentResultOutput) DeploymentType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.DeploymentType }).(pulumi.StringOutput)
}

// Deployment identifier which can be renamed and is not necessarily unique. Avoid entering confidential information.
func (o LookupDeploymentResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
func (o LookupDeploymentResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDeploymentResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Unique identifier that is immutable on creation.
func (o LookupDeploymentResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o LookupDeploymentResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Specifies the OCID of the previous deployment to be redeployed.
func (o LookupDeploymentResultOutput) PreviousDeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.PreviousDeploymentId }).(pulumi.StringOutput)
}

// The OCID of a project.
func (o LookupDeploymentResultOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.ProjectId }).(pulumi.StringOutput)
}

// The current state of the deployment.
func (o LookupDeploymentResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupDeploymentResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDeploymentResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// Time the deployment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o LookupDeploymentResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// Time the deployment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o LookupDeploymentResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func (o LookupDeploymentResultOutput) TriggerNewDevopsDeployment() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDeploymentResult) bool { return v.TriggerNewDevopsDeployment }).(pulumi.BoolOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDeploymentResultOutput{})
}
