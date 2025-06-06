// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datascience

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type ModelArtifactExport struct {
	pulumi.CustomResourceState

	ArtifactSourceType pulumi.StringOutput `pulumi:"artifactSourceType"`
	ModelId            pulumi.StringOutput `pulumi:"modelId"`
	Namespace          pulumi.StringOutput `pulumi:"namespace"`
	SourceBucket       pulumi.StringOutput `pulumi:"sourceBucket"`
	SourceObjectName   pulumi.StringOutput `pulumi:"sourceObjectName"`
	SourceRegion       pulumi.StringOutput `pulumi:"sourceRegion"`
}

// NewModelArtifactExport registers a new resource with the given unique name, arguments, and options.
func NewModelArtifactExport(ctx *pulumi.Context,
	name string, args *ModelArtifactExportArgs, opts ...pulumi.ResourceOption) (*ModelArtifactExport, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ArtifactSourceType == nil {
		return nil, errors.New("invalid value for required argument 'ArtifactSourceType'")
	}
	if args.ModelId == nil {
		return nil, errors.New("invalid value for required argument 'ModelId'")
	}
	if args.Namespace == nil {
		return nil, errors.New("invalid value for required argument 'Namespace'")
	}
	if args.SourceBucket == nil {
		return nil, errors.New("invalid value for required argument 'SourceBucket'")
	}
	if args.SourceObjectName == nil {
		return nil, errors.New("invalid value for required argument 'SourceObjectName'")
	}
	if args.SourceRegion == nil {
		return nil, errors.New("invalid value for required argument 'SourceRegion'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ModelArtifactExport
	err := ctx.RegisterResource("oci:DataScience/modelArtifactExport:ModelArtifactExport", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetModelArtifactExport gets an existing ModelArtifactExport resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetModelArtifactExport(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ModelArtifactExportState, opts ...pulumi.ResourceOption) (*ModelArtifactExport, error) {
	var resource ModelArtifactExport
	err := ctx.ReadResource("oci:DataScience/modelArtifactExport:ModelArtifactExport", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ModelArtifactExport resources.
type modelArtifactExportState struct {
	ArtifactSourceType *string `pulumi:"artifactSourceType"`
	ModelId            *string `pulumi:"modelId"`
	Namespace          *string `pulumi:"namespace"`
	SourceBucket       *string `pulumi:"sourceBucket"`
	SourceObjectName   *string `pulumi:"sourceObjectName"`
	SourceRegion       *string `pulumi:"sourceRegion"`
}

type ModelArtifactExportState struct {
	ArtifactSourceType pulumi.StringPtrInput
	ModelId            pulumi.StringPtrInput
	Namespace          pulumi.StringPtrInput
	SourceBucket       pulumi.StringPtrInput
	SourceObjectName   pulumi.StringPtrInput
	SourceRegion       pulumi.StringPtrInput
}

func (ModelArtifactExportState) ElementType() reflect.Type {
	return reflect.TypeOf((*modelArtifactExportState)(nil)).Elem()
}

type modelArtifactExportArgs struct {
	ArtifactSourceType string `pulumi:"artifactSourceType"`
	ModelId            string `pulumi:"modelId"`
	Namespace          string `pulumi:"namespace"`
	SourceBucket       string `pulumi:"sourceBucket"`
	SourceObjectName   string `pulumi:"sourceObjectName"`
	SourceRegion       string `pulumi:"sourceRegion"`
}

// The set of arguments for constructing a ModelArtifactExport resource.
type ModelArtifactExportArgs struct {
	ArtifactSourceType pulumi.StringInput
	ModelId            pulumi.StringInput
	Namespace          pulumi.StringInput
	SourceBucket       pulumi.StringInput
	SourceObjectName   pulumi.StringInput
	SourceRegion       pulumi.StringInput
}

func (ModelArtifactExportArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*modelArtifactExportArgs)(nil)).Elem()
}

type ModelArtifactExportInput interface {
	pulumi.Input

	ToModelArtifactExportOutput() ModelArtifactExportOutput
	ToModelArtifactExportOutputWithContext(ctx context.Context) ModelArtifactExportOutput
}

func (*ModelArtifactExport) ElementType() reflect.Type {
	return reflect.TypeOf((**ModelArtifactExport)(nil)).Elem()
}

func (i *ModelArtifactExport) ToModelArtifactExportOutput() ModelArtifactExportOutput {
	return i.ToModelArtifactExportOutputWithContext(context.Background())
}

func (i *ModelArtifactExport) ToModelArtifactExportOutputWithContext(ctx context.Context) ModelArtifactExportOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ModelArtifactExportOutput)
}

// ModelArtifactExportArrayInput is an input type that accepts ModelArtifactExportArray and ModelArtifactExportArrayOutput values.
// You can construct a concrete instance of `ModelArtifactExportArrayInput` via:
//
//	ModelArtifactExportArray{ ModelArtifactExportArgs{...} }
type ModelArtifactExportArrayInput interface {
	pulumi.Input

	ToModelArtifactExportArrayOutput() ModelArtifactExportArrayOutput
	ToModelArtifactExportArrayOutputWithContext(context.Context) ModelArtifactExportArrayOutput
}

type ModelArtifactExportArray []ModelArtifactExportInput

func (ModelArtifactExportArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ModelArtifactExport)(nil)).Elem()
}

func (i ModelArtifactExportArray) ToModelArtifactExportArrayOutput() ModelArtifactExportArrayOutput {
	return i.ToModelArtifactExportArrayOutputWithContext(context.Background())
}

func (i ModelArtifactExportArray) ToModelArtifactExportArrayOutputWithContext(ctx context.Context) ModelArtifactExportArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ModelArtifactExportArrayOutput)
}

// ModelArtifactExportMapInput is an input type that accepts ModelArtifactExportMap and ModelArtifactExportMapOutput values.
// You can construct a concrete instance of `ModelArtifactExportMapInput` via:
//
//	ModelArtifactExportMap{ "key": ModelArtifactExportArgs{...} }
type ModelArtifactExportMapInput interface {
	pulumi.Input

	ToModelArtifactExportMapOutput() ModelArtifactExportMapOutput
	ToModelArtifactExportMapOutputWithContext(context.Context) ModelArtifactExportMapOutput
}

type ModelArtifactExportMap map[string]ModelArtifactExportInput

func (ModelArtifactExportMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ModelArtifactExport)(nil)).Elem()
}

func (i ModelArtifactExportMap) ToModelArtifactExportMapOutput() ModelArtifactExportMapOutput {
	return i.ToModelArtifactExportMapOutputWithContext(context.Background())
}

func (i ModelArtifactExportMap) ToModelArtifactExportMapOutputWithContext(ctx context.Context) ModelArtifactExportMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ModelArtifactExportMapOutput)
}

type ModelArtifactExportOutput struct{ *pulumi.OutputState }

func (ModelArtifactExportOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ModelArtifactExport)(nil)).Elem()
}

func (o ModelArtifactExportOutput) ToModelArtifactExportOutput() ModelArtifactExportOutput {
	return o
}

func (o ModelArtifactExportOutput) ToModelArtifactExportOutputWithContext(ctx context.Context) ModelArtifactExportOutput {
	return o
}

func (o ModelArtifactExportOutput) ArtifactSourceType() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelArtifactExport) pulumi.StringOutput { return v.ArtifactSourceType }).(pulumi.StringOutput)
}

func (o ModelArtifactExportOutput) ModelId() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelArtifactExport) pulumi.StringOutput { return v.ModelId }).(pulumi.StringOutput)
}

func (o ModelArtifactExportOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelArtifactExport) pulumi.StringOutput { return v.Namespace }).(pulumi.StringOutput)
}

func (o ModelArtifactExportOutput) SourceBucket() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelArtifactExport) pulumi.StringOutput { return v.SourceBucket }).(pulumi.StringOutput)
}

func (o ModelArtifactExportOutput) SourceObjectName() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelArtifactExport) pulumi.StringOutput { return v.SourceObjectName }).(pulumi.StringOutput)
}

func (o ModelArtifactExportOutput) SourceRegion() pulumi.StringOutput {
	return o.ApplyT(func(v *ModelArtifactExport) pulumi.StringOutput { return v.SourceRegion }).(pulumi.StringOutput)
}

type ModelArtifactExportArrayOutput struct{ *pulumi.OutputState }

func (ModelArtifactExportArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ModelArtifactExport)(nil)).Elem()
}

func (o ModelArtifactExportArrayOutput) ToModelArtifactExportArrayOutput() ModelArtifactExportArrayOutput {
	return o
}

func (o ModelArtifactExportArrayOutput) ToModelArtifactExportArrayOutputWithContext(ctx context.Context) ModelArtifactExportArrayOutput {
	return o
}

func (o ModelArtifactExportArrayOutput) Index(i pulumi.IntInput) ModelArtifactExportOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ModelArtifactExport {
		return vs[0].([]*ModelArtifactExport)[vs[1].(int)]
	}).(ModelArtifactExportOutput)
}

type ModelArtifactExportMapOutput struct{ *pulumi.OutputState }

func (ModelArtifactExportMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ModelArtifactExport)(nil)).Elem()
}

func (o ModelArtifactExportMapOutput) ToModelArtifactExportMapOutput() ModelArtifactExportMapOutput {
	return o
}

func (o ModelArtifactExportMapOutput) ToModelArtifactExportMapOutputWithContext(ctx context.Context) ModelArtifactExportMapOutput {
	return o
}

func (o ModelArtifactExportMapOutput) MapIndex(k pulumi.StringInput) ModelArtifactExportOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ModelArtifactExport {
		return vs[0].(map[string]*ModelArtifactExport)[vs[1].(string)]
	}).(ModelArtifactExportOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ModelArtifactExportInput)(nil)).Elem(), &ModelArtifactExport{})
	pulumi.RegisterInputType(reflect.TypeOf((*ModelArtifactExportArrayInput)(nil)).Elem(), ModelArtifactExportArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ModelArtifactExportMapInput)(nil)).Elem(), ModelArtifactExportMap{})
	pulumi.RegisterOutputType(ModelArtifactExportOutput{})
	pulumi.RegisterOutputType(ModelArtifactExportArrayOutput{})
	pulumi.RegisterOutputType(ModelArtifactExportMapOutput{})
}
