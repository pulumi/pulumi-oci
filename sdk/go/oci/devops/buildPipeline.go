// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Build Pipeline resource in Oracle Cloud Infrastructure Devops service.
//
// Creates a new build pipeline.
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
//			_, err := devops.NewBuildPipeline(ctx, "test_build_pipeline", &devops.BuildPipelineArgs{
//				ProjectId: pulumi.Any(testProject.Id),
//				BuildPipelineParameters: &devops.BuildPipelineBuildPipelineParametersArgs{
//					Items: devops.BuildPipelineBuildPipelineParametersItemArray{
//						&devops.BuildPipelineBuildPipelineParametersItemArgs{
//							DefaultValue: pulumi.Any(buildPipelineBuildPipelineParametersItemsDefaultValue),
//							Name:         pulumi.Any(buildPipelineBuildPipelineParametersItemsName),
//							Description:  pulumi.Any(buildPipelineBuildPipelineParametersItemsDescription),
//						},
//					},
//				},
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(buildPipelineDescription),
//				DisplayName: pulumi.Any(buildPipelineDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// BuildPipelines can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DevOps/buildPipeline:BuildPipeline test_build_pipeline "id"
// ```
type BuildPipeline struct {
	pulumi.CustomResourceState

	// (Updatable) Specifies list of parameters present in a build pipeline. An UPDATE operation replaces the existing parameters list entirely.
	BuildPipelineParameters BuildPipelineBuildPipelineParametersOutput `pulumi:"buildPipelineParameters"`
	// The OCID of the compartment where the build pipeline is created.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Optional description about the build pipeline.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Build pipeline display name. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The OCID of the DevOps project.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// The current state of the build pipeline.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time the build pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the build pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewBuildPipeline registers a new resource with the given unique name, arguments, and options.
func NewBuildPipeline(ctx *pulumi.Context,
	name string, args *BuildPipelineArgs, opts ...pulumi.ResourceOption) (*BuildPipeline, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ProjectId == nil {
		return nil, errors.New("invalid value for required argument 'ProjectId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource BuildPipeline
	err := ctx.RegisterResource("oci:DevOps/buildPipeline:BuildPipeline", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetBuildPipeline gets an existing BuildPipeline resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetBuildPipeline(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *BuildPipelineState, opts ...pulumi.ResourceOption) (*BuildPipeline, error) {
	var resource BuildPipeline
	err := ctx.ReadResource("oci:DevOps/buildPipeline:BuildPipeline", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering BuildPipeline resources.
type buildPipelineState struct {
	// (Updatable) Specifies list of parameters present in a build pipeline. An UPDATE operation replaces the existing parameters list entirely.
	BuildPipelineParameters *BuildPipelineBuildPipelineParameters `pulumi:"buildPipelineParameters"`
	// The OCID of the compartment where the build pipeline is created.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Optional description about the build pipeline.
	Description *string `pulumi:"description"`
	// (Updatable) Build pipeline display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The OCID of the DevOps project.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId *string `pulumi:"projectId"`
	// The current state of the build pipeline.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time the build pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the build pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type BuildPipelineState struct {
	// (Updatable) Specifies list of parameters present in a build pipeline. An UPDATE operation replaces the existing parameters list entirely.
	BuildPipelineParameters BuildPipelineBuildPipelineParametersPtrInput
	// The OCID of the compartment where the build pipeline is created.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Optional description about the build pipeline.
	Description pulumi.StringPtrInput
	// (Updatable) Build pipeline display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The OCID of the DevOps project.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId pulumi.StringPtrInput
	// The current state of the build pipeline.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time the build pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The time the build pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
}

func (BuildPipelineState) ElementType() reflect.Type {
	return reflect.TypeOf((*buildPipelineState)(nil)).Elem()
}

type buildPipelineArgs struct {
	// (Updatable) Specifies list of parameters present in a build pipeline. An UPDATE operation replaces the existing parameters list entirely.
	BuildPipelineParameters *BuildPipelineBuildPipelineParameters `pulumi:"buildPipelineParameters"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Optional description about the build pipeline.
	Description *string `pulumi:"description"`
	// (Updatable) Build pipeline display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the DevOps project.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId string `pulumi:"projectId"`
}

// The set of arguments for constructing a BuildPipeline resource.
type BuildPipelineArgs struct {
	// (Updatable) Specifies list of parameters present in a build pipeline. An UPDATE operation replaces the existing parameters list entirely.
	BuildPipelineParameters BuildPipelineBuildPipelineParametersPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Optional description about the build pipeline.
	Description pulumi.StringPtrInput
	// (Updatable) Build pipeline display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// The OCID of the DevOps project.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId pulumi.StringInput
}

func (BuildPipelineArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*buildPipelineArgs)(nil)).Elem()
}

type BuildPipelineInput interface {
	pulumi.Input

	ToBuildPipelineOutput() BuildPipelineOutput
	ToBuildPipelineOutputWithContext(ctx context.Context) BuildPipelineOutput
}

func (*BuildPipeline) ElementType() reflect.Type {
	return reflect.TypeOf((**BuildPipeline)(nil)).Elem()
}

func (i *BuildPipeline) ToBuildPipelineOutput() BuildPipelineOutput {
	return i.ToBuildPipelineOutputWithContext(context.Background())
}

func (i *BuildPipeline) ToBuildPipelineOutputWithContext(ctx context.Context) BuildPipelineOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BuildPipelineOutput)
}

// BuildPipelineArrayInput is an input type that accepts BuildPipelineArray and BuildPipelineArrayOutput values.
// You can construct a concrete instance of `BuildPipelineArrayInput` via:
//
//	BuildPipelineArray{ BuildPipelineArgs{...} }
type BuildPipelineArrayInput interface {
	pulumi.Input

	ToBuildPipelineArrayOutput() BuildPipelineArrayOutput
	ToBuildPipelineArrayOutputWithContext(context.Context) BuildPipelineArrayOutput
}

type BuildPipelineArray []BuildPipelineInput

func (BuildPipelineArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*BuildPipeline)(nil)).Elem()
}

func (i BuildPipelineArray) ToBuildPipelineArrayOutput() BuildPipelineArrayOutput {
	return i.ToBuildPipelineArrayOutputWithContext(context.Background())
}

func (i BuildPipelineArray) ToBuildPipelineArrayOutputWithContext(ctx context.Context) BuildPipelineArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BuildPipelineArrayOutput)
}

// BuildPipelineMapInput is an input type that accepts BuildPipelineMap and BuildPipelineMapOutput values.
// You can construct a concrete instance of `BuildPipelineMapInput` via:
//
//	BuildPipelineMap{ "key": BuildPipelineArgs{...} }
type BuildPipelineMapInput interface {
	pulumi.Input

	ToBuildPipelineMapOutput() BuildPipelineMapOutput
	ToBuildPipelineMapOutputWithContext(context.Context) BuildPipelineMapOutput
}

type BuildPipelineMap map[string]BuildPipelineInput

func (BuildPipelineMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*BuildPipeline)(nil)).Elem()
}

func (i BuildPipelineMap) ToBuildPipelineMapOutput() BuildPipelineMapOutput {
	return i.ToBuildPipelineMapOutputWithContext(context.Background())
}

func (i BuildPipelineMap) ToBuildPipelineMapOutputWithContext(ctx context.Context) BuildPipelineMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(BuildPipelineMapOutput)
}

type BuildPipelineOutput struct{ *pulumi.OutputState }

func (BuildPipelineOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**BuildPipeline)(nil)).Elem()
}

func (o BuildPipelineOutput) ToBuildPipelineOutput() BuildPipelineOutput {
	return o
}

func (o BuildPipelineOutput) ToBuildPipelineOutputWithContext(ctx context.Context) BuildPipelineOutput {
	return o
}

// (Updatable) Specifies list of parameters present in a build pipeline. An UPDATE operation replaces the existing parameters list entirely.
func (o BuildPipelineOutput) BuildPipelineParameters() BuildPipelineBuildPipelineParametersOutput {
	return o.ApplyT(func(v *BuildPipeline) BuildPipelineBuildPipelineParametersOutput { return v.BuildPipelineParameters }).(BuildPipelineBuildPipelineParametersOutput)
}

// The OCID of the compartment where the build pipeline is created.
func (o BuildPipelineOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
func (o BuildPipelineOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Optional description about the build pipeline.
func (o BuildPipelineOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Build pipeline display name. Avoid entering confidential information.
func (o BuildPipelineOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
func (o BuildPipelineOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o BuildPipelineOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The OCID of the DevOps project.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o BuildPipelineOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringOutput { return v.ProjectId }).(pulumi.StringOutput)
}

// The current state of the build pipeline.
func (o BuildPipelineOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o BuildPipelineOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time the build pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o BuildPipelineOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the build pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o BuildPipelineOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *BuildPipeline) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type BuildPipelineArrayOutput struct{ *pulumi.OutputState }

func (BuildPipelineArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*BuildPipeline)(nil)).Elem()
}

func (o BuildPipelineArrayOutput) ToBuildPipelineArrayOutput() BuildPipelineArrayOutput {
	return o
}

func (o BuildPipelineArrayOutput) ToBuildPipelineArrayOutputWithContext(ctx context.Context) BuildPipelineArrayOutput {
	return o
}

func (o BuildPipelineArrayOutput) Index(i pulumi.IntInput) BuildPipelineOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *BuildPipeline {
		return vs[0].([]*BuildPipeline)[vs[1].(int)]
	}).(BuildPipelineOutput)
}

type BuildPipelineMapOutput struct{ *pulumi.OutputState }

func (BuildPipelineMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*BuildPipeline)(nil)).Elem()
}

func (o BuildPipelineMapOutput) ToBuildPipelineMapOutput() BuildPipelineMapOutput {
	return o
}

func (o BuildPipelineMapOutput) ToBuildPipelineMapOutputWithContext(ctx context.Context) BuildPipelineMapOutput {
	return o
}

func (o BuildPipelineMapOutput) MapIndex(k pulumi.StringInput) BuildPipelineOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *BuildPipeline {
		return vs[0].(map[string]*BuildPipeline)[vs[1].(string)]
	}).(BuildPipelineOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*BuildPipelineInput)(nil)).Elem(), &BuildPipeline{})
	pulumi.RegisterInputType(reflect.TypeOf((*BuildPipelineArrayInput)(nil)).Elem(), BuildPipelineArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*BuildPipelineMapInput)(nil)).Elem(), BuildPipelineMap{})
	pulumi.RegisterOutputType(BuildPipelineOutput{})
	pulumi.RegisterOutputType(BuildPipelineArrayOutput{})
	pulumi.RegisterOutputType(BuildPipelineMapOutput{})
}
