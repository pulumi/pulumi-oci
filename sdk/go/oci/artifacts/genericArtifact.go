// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package artifacts

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Generic Artifact resource in Oracle Cloud Infrastructure Artifacts service.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/artifacts"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := artifacts.NewGenericArtifact(ctx, "test_generic_artifact", &artifacts.GenericArtifactArgs{
//				ArtifactId: pulumi.Any(testArtifact.Id),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
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
// GenericArtifacts can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Artifacts/genericArtifact:GenericArtifact test_generic_artifact "generic/artifacts/{artifactId}"
// ```
type GenericArtifact struct {
	pulumi.CustomResourceState

	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
	ArtifactId pulumi.StringOutput `pulumi:"artifactId"`
	// A user-defined path to describe the location of an artifact. Slashes do not create a directory structure, but you can use slashes to organize the repository. An artifact path does not include an artifact version.  Example: `project01/my-web-app/artifact-abc`
	ArtifactPath pulumi.StringOutput `pulumi:"artifactPath"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository's compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// The artifact name with the format of `<artifact-path>:<artifact-version>`. The artifact name is truncated to a maximum length of 255.  Example: `project01/my-web-app/artifact-abc:1.0.0`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.
	RepositoryId pulumi.StringOutput `pulumi:"repositoryId"`
	// The SHA256 digest for the artifact. When you upload an artifact to the repository, a SHA256 digest is calculated and added to the artifact properties.
	Sha256 pulumi.StringOutput `pulumi:"sha256"`
	// The size of the artifact in bytes.
	SizeInBytes pulumi.StringOutput `pulumi:"sizeInBytes"`
	// The current state of the artifact.
	State pulumi.StringOutput `pulumi:"state"`
	// An RFC 3339 timestamp indicating when the repository was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// A user-defined string to describe the artifact version.  Example: `1.1.0` or `1.2-beta-2`
	Version pulumi.StringOutput `pulumi:"version"`
}

// NewGenericArtifact registers a new resource with the given unique name, arguments, and options.
func NewGenericArtifact(ctx *pulumi.Context,
	name string, args *GenericArtifactArgs, opts ...pulumi.ResourceOption) (*GenericArtifact, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ArtifactId == nil {
		return nil, errors.New("invalid value for required argument 'ArtifactId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource GenericArtifact
	err := ctx.RegisterResource("oci:Artifacts/genericArtifact:GenericArtifact", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetGenericArtifact gets an existing GenericArtifact resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetGenericArtifact(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *GenericArtifactState, opts ...pulumi.ResourceOption) (*GenericArtifact, error) {
	var resource GenericArtifact
	err := ctx.ReadResource("oci:Artifacts/genericArtifact:GenericArtifact", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering GenericArtifact resources.
type genericArtifactState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
	ArtifactId *string `pulumi:"artifactId"`
	// A user-defined path to describe the location of an artifact. Slashes do not create a directory structure, but you can use slashes to organize the repository. An artifact path does not include an artifact version.  Example: `project01/my-web-app/artifact-abc`
	ArtifactPath *string `pulumi:"artifactPath"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository's compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The artifact name with the format of `<artifact-path>:<artifact-version>`. The artifact name is truncated to a maximum length of 255.  Example: `project01/my-web-app/artifact-abc:1.0.0`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.
	RepositoryId *string `pulumi:"repositoryId"`
	// The SHA256 digest for the artifact. When you upload an artifact to the repository, a SHA256 digest is calculated and added to the artifact properties.
	Sha256 *string `pulumi:"sha256"`
	// The size of the artifact in bytes.
	SizeInBytes *string `pulumi:"sizeInBytes"`
	// The current state of the artifact.
	State *string `pulumi:"state"`
	// An RFC 3339 timestamp indicating when the repository was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// A user-defined string to describe the artifact version.  Example: `1.1.0` or `1.2-beta-2`
	Version *string `pulumi:"version"`
}

type GenericArtifactState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
	ArtifactId pulumi.StringPtrInput
	// A user-defined path to describe the location of an artifact. Slashes do not create a directory structure, but you can use slashes to organize the repository. An artifact path does not include an artifact version.  Example: `project01/my-web-app/artifact-abc`
	ArtifactPath pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository's compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// The artifact name with the format of `<artifact-path>:<artifact-version>`. The artifact name is truncated to a maximum length of 255.  Example: `project01/my-web-app/artifact-abc:1.0.0`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.
	RepositoryId pulumi.StringPtrInput
	// The SHA256 digest for the artifact. When you upload an artifact to the repository, a SHA256 digest is calculated and added to the artifact properties.
	Sha256 pulumi.StringPtrInput
	// The size of the artifact in bytes.
	SizeInBytes pulumi.StringPtrInput
	// The current state of the artifact.
	State pulumi.StringPtrInput
	// An RFC 3339 timestamp indicating when the repository was created.
	TimeCreated pulumi.StringPtrInput
	// A user-defined string to describe the artifact version.  Example: `1.1.0` or `1.2-beta-2`
	Version pulumi.StringPtrInput
}

func (GenericArtifactState) ElementType() reflect.Type {
	return reflect.TypeOf((*genericArtifactState)(nil)).Elem()
}

type genericArtifactArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
	ArtifactId string `pulumi:"artifactId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a GenericArtifact resource.
type GenericArtifactArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
	ArtifactId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (GenericArtifactArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*genericArtifactArgs)(nil)).Elem()
}

type GenericArtifactInput interface {
	pulumi.Input

	ToGenericArtifactOutput() GenericArtifactOutput
	ToGenericArtifactOutputWithContext(ctx context.Context) GenericArtifactOutput
}

func (*GenericArtifact) ElementType() reflect.Type {
	return reflect.TypeOf((**GenericArtifact)(nil)).Elem()
}

func (i *GenericArtifact) ToGenericArtifactOutput() GenericArtifactOutput {
	return i.ToGenericArtifactOutputWithContext(context.Background())
}

func (i *GenericArtifact) ToGenericArtifactOutputWithContext(ctx context.Context) GenericArtifactOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GenericArtifactOutput)
}

// GenericArtifactArrayInput is an input type that accepts GenericArtifactArray and GenericArtifactArrayOutput values.
// You can construct a concrete instance of `GenericArtifactArrayInput` via:
//
//	GenericArtifactArray{ GenericArtifactArgs{...} }
type GenericArtifactArrayInput interface {
	pulumi.Input

	ToGenericArtifactArrayOutput() GenericArtifactArrayOutput
	ToGenericArtifactArrayOutputWithContext(context.Context) GenericArtifactArrayOutput
}

type GenericArtifactArray []GenericArtifactInput

func (GenericArtifactArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*GenericArtifact)(nil)).Elem()
}

func (i GenericArtifactArray) ToGenericArtifactArrayOutput() GenericArtifactArrayOutput {
	return i.ToGenericArtifactArrayOutputWithContext(context.Background())
}

func (i GenericArtifactArray) ToGenericArtifactArrayOutputWithContext(ctx context.Context) GenericArtifactArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GenericArtifactArrayOutput)
}

// GenericArtifactMapInput is an input type that accepts GenericArtifactMap and GenericArtifactMapOutput values.
// You can construct a concrete instance of `GenericArtifactMapInput` via:
//
//	GenericArtifactMap{ "key": GenericArtifactArgs{...} }
type GenericArtifactMapInput interface {
	pulumi.Input

	ToGenericArtifactMapOutput() GenericArtifactMapOutput
	ToGenericArtifactMapOutputWithContext(context.Context) GenericArtifactMapOutput
}

type GenericArtifactMap map[string]GenericArtifactInput

func (GenericArtifactMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*GenericArtifact)(nil)).Elem()
}

func (i GenericArtifactMap) ToGenericArtifactMapOutput() GenericArtifactMapOutput {
	return i.ToGenericArtifactMapOutputWithContext(context.Background())
}

func (i GenericArtifactMap) ToGenericArtifactMapOutputWithContext(ctx context.Context) GenericArtifactMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GenericArtifactMapOutput)
}

type GenericArtifactOutput struct{ *pulumi.OutputState }

func (GenericArtifactOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**GenericArtifact)(nil)).Elem()
}

func (o GenericArtifactOutput) ToGenericArtifactOutput() GenericArtifactOutput {
	return o
}

func (o GenericArtifactOutput) ToGenericArtifactOutputWithContext(ctx context.Context) GenericArtifactOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
func (o GenericArtifactOutput) ArtifactId() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.ArtifactId }).(pulumi.StringOutput)
}

// A user-defined path to describe the location of an artifact. Slashes do not create a directory structure, but you can use slashes to organize the repository. An artifact path does not include an artifact version.  Example: `project01/my-web-app/artifact-abc`
func (o GenericArtifactOutput) ArtifactPath() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.ArtifactPath }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository's compartment.
func (o GenericArtifactOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o GenericArtifactOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The artifact name with the format of `<artifact-path>:<artifact-version>`. The artifact name is truncated to a maximum length of 255.  Example: `project01/my-web-app/artifact-abc:1.0.0`
func (o GenericArtifactOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o GenericArtifactOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.
func (o GenericArtifactOutput) RepositoryId() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.RepositoryId }).(pulumi.StringOutput)
}

// The SHA256 digest for the artifact. When you upload an artifact to the repository, a SHA256 digest is calculated and added to the artifact properties.
func (o GenericArtifactOutput) Sha256() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.Sha256 }).(pulumi.StringOutput)
}

// The size of the artifact in bytes.
func (o GenericArtifactOutput) SizeInBytes() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.SizeInBytes }).(pulumi.StringOutput)
}

// The current state of the artifact.
func (o GenericArtifactOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// An RFC 3339 timestamp indicating when the repository was created.
func (o GenericArtifactOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// A user-defined string to describe the artifact version.  Example: `1.1.0` or `1.2-beta-2`
func (o GenericArtifactOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v *GenericArtifact) pulumi.StringOutput { return v.Version }).(pulumi.StringOutput)
}

type GenericArtifactArrayOutput struct{ *pulumi.OutputState }

func (GenericArtifactArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*GenericArtifact)(nil)).Elem()
}

func (o GenericArtifactArrayOutput) ToGenericArtifactArrayOutput() GenericArtifactArrayOutput {
	return o
}

func (o GenericArtifactArrayOutput) ToGenericArtifactArrayOutputWithContext(ctx context.Context) GenericArtifactArrayOutput {
	return o
}

func (o GenericArtifactArrayOutput) Index(i pulumi.IntInput) GenericArtifactOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *GenericArtifact {
		return vs[0].([]*GenericArtifact)[vs[1].(int)]
	}).(GenericArtifactOutput)
}

type GenericArtifactMapOutput struct{ *pulumi.OutputState }

func (GenericArtifactMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*GenericArtifact)(nil)).Elem()
}

func (o GenericArtifactMapOutput) ToGenericArtifactMapOutput() GenericArtifactMapOutput {
	return o
}

func (o GenericArtifactMapOutput) ToGenericArtifactMapOutputWithContext(ctx context.Context) GenericArtifactMapOutput {
	return o
}

func (o GenericArtifactMapOutput) MapIndex(k pulumi.StringInput) GenericArtifactOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *GenericArtifact {
		return vs[0].(map[string]*GenericArtifact)[vs[1].(string)]
	}).(GenericArtifactOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*GenericArtifactInput)(nil)).Elem(), &GenericArtifact{})
	pulumi.RegisterInputType(reflect.TypeOf((*GenericArtifactArrayInput)(nil)).Elem(), GenericArtifactArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*GenericArtifactMapInput)(nil)).Elem(), GenericArtifactMap{})
	pulumi.RegisterOutputType(GenericArtifactOutput{})
	pulumi.RegisterOutputType(GenericArtifactArrayOutput{})
	pulumi.RegisterOutputType(GenericArtifactMapOutput{})
}
