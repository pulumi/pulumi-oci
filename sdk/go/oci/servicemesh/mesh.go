// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package servicemesh

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Mesh resource in Oracle Cloud Infrastructure Service Mesh service.
//
// Creates a new Mesh.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ServiceMesh"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ServiceMesh.NewMesh(ctx, "testMesh", &ServiceMesh.MeshArgs{
//				CertificateAuthorities: servicemesh.MeshCertificateAuthorityArray{
//					&servicemesh.MeshCertificateAuthorityArgs{
//						Id: pulumi.Any(_var.Mesh_certificate_authorities_id),
//					},
//				},
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				DisplayName:   pulumi.Any(_var.Mesh_display_name),
//				DefinedTags: pulumi.AnyMap{
//					"foo-namespace.bar-key": pulumi.Any("value"),
//				},
//				Description: pulumi.Any(_var.Mesh_description),
//				FreeformTags: pulumi.AnyMap{
//					"bar-key": pulumi.Any("value"),
//				},
//				Mtls: &servicemesh.MeshMtlsArgs{
//					Minimum: pulumi.Any(_var.Mesh_mtls_minimum),
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
// Meshes can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:ServiceMesh/mesh:Mesh test_mesh "id"
//
// ```
type Mesh struct {
	pulumi.CustomResourceState

	// The OCID of the certificate authority resource OCID to use for creating leaf certificates.
	CertificateAuthorities MeshCertificateAuthorityArrayOutput `pulumi:"certificateAuthorities"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) A user-friendly name. The name does not have to be unique and can be changed after creation. Avoid entering confidential information.  Example: `My new resource`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) Sets a minimum level of mTLS authentication for all virtual services within the mesh.
	Mtls MeshMtlsOutput `pulumi:"mtls"`
	// The current state of the Resource.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewMesh registers a new resource with the given unique name, arguments, and options.
func NewMesh(ctx *pulumi.Context,
	name string, args *MeshArgs, opts ...pulumi.ResourceOption) (*Mesh, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CertificateAuthorities == nil {
		return nil, errors.New("invalid value for required argument 'CertificateAuthorities'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	var resource Mesh
	err := ctx.RegisterResource("oci:ServiceMesh/mesh:Mesh", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMesh gets an existing Mesh resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMesh(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MeshState, opts ...pulumi.ResourceOption) (*Mesh, error) {
	var resource Mesh
	err := ctx.ReadResource("oci:ServiceMesh/mesh:Mesh", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Mesh resources.
type meshState struct {
	// The OCID of the certificate authority resource OCID to use for creating leaf certificates.
	CertificateAuthorities []MeshCertificateAuthority `pulumi:"certificateAuthorities"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name. The name does not have to be unique and can be changed after creation. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) Sets a minimum level of mTLS authentication for all virtual services within the mesh.
	Mtls *MeshMtls `pulumi:"mtls"`
	// The current state of the Resource.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type MeshState struct {
	// The OCID of the certificate authority resource OCID to use for creating leaf certificates.
	CertificateAuthorities MeshCertificateAuthorityArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name. The name does not have to be unique and can be changed after creation. Avoid entering confidential information.  Example: `My new resource`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) Sets a minimum level of mTLS authentication for all virtual services within the mesh.
	Mtls MeshMtlsPtrInput
	// The current state of the Resource.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (MeshState) ElementType() reflect.Type {
	return reflect.TypeOf((*meshState)(nil)).Elem()
}

type meshArgs struct {
	// The OCID of the certificate authority resource OCID to use for creating leaf certificates.
	CertificateAuthorities []MeshCertificateAuthority `pulumi:"certificateAuthorities"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name. The name does not have to be unique and can be changed after creation. Avoid entering confidential information.  Example: `My new resource`
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) Sets a minimum level of mTLS authentication for all virtual services within the mesh.
	Mtls *MeshMtls `pulumi:"mtls"`
}

// The set of arguments for constructing a Mesh resource.
type MeshArgs struct {
	// The OCID of the certificate authority resource OCID to use for creating leaf certificates.
	CertificateAuthorities MeshCertificateAuthorityArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name. The name does not have to be unique and can be changed after creation. Avoid entering confidential information.  Example: `My new resource`
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) Sets a minimum level of mTLS authentication for all virtual services within the mesh.
	Mtls MeshMtlsPtrInput
}

func (MeshArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*meshArgs)(nil)).Elem()
}

type MeshInput interface {
	pulumi.Input

	ToMeshOutput() MeshOutput
	ToMeshOutputWithContext(ctx context.Context) MeshOutput
}

func (*Mesh) ElementType() reflect.Type {
	return reflect.TypeOf((**Mesh)(nil)).Elem()
}

func (i *Mesh) ToMeshOutput() MeshOutput {
	return i.ToMeshOutputWithContext(context.Background())
}

func (i *Mesh) ToMeshOutputWithContext(ctx context.Context) MeshOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MeshOutput)
}

// MeshArrayInput is an input type that accepts MeshArray and MeshArrayOutput values.
// You can construct a concrete instance of `MeshArrayInput` via:
//
//	MeshArray{ MeshArgs{...} }
type MeshArrayInput interface {
	pulumi.Input

	ToMeshArrayOutput() MeshArrayOutput
	ToMeshArrayOutputWithContext(context.Context) MeshArrayOutput
}

type MeshArray []MeshInput

func (MeshArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Mesh)(nil)).Elem()
}

func (i MeshArray) ToMeshArrayOutput() MeshArrayOutput {
	return i.ToMeshArrayOutputWithContext(context.Background())
}

func (i MeshArray) ToMeshArrayOutputWithContext(ctx context.Context) MeshArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MeshArrayOutput)
}

// MeshMapInput is an input type that accepts MeshMap and MeshMapOutput values.
// You can construct a concrete instance of `MeshMapInput` via:
//
//	MeshMap{ "key": MeshArgs{...} }
type MeshMapInput interface {
	pulumi.Input

	ToMeshMapOutput() MeshMapOutput
	ToMeshMapOutputWithContext(context.Context) MeshMapOutput
}

type MeshMap map[string]MeshInput

func (MeshMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Mesh)(nil)).Elem()
}

func (i MeshMap) ToMeshMapOutput() MeshMapOutput {
	return i.ToMeshMapOutputWithContext(context.Background())
}

func (i MeshMap) ToMeshMapOutputWithContext(ctx context.Context) MeshMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MeshMapOutput)
}

type MeshOutput struct{ *pulumi.OutputState }

func (MeshOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Mesh)(nil)).Elem()
}

func (o MeshOutput) ToMeshOutput() MeshOutput {
	return o
}

func (o MeshOutput) ToMeshOutputWithContext(ctx context.Context) MeshOutput {
	return o
}

// The OCID of the certificate authority resource OCID to use for creating leaf certificates.
func (o MeshOutput) CertificateAuthorities() MeshCertificateAuthorityArrayOutput {
	return o.ApplyT(func(v *Mesh) MeshCertificateAuthorityArrayOutput { return v.CertificateAuthorities }).(MeshCertificateAuthorityArrayOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o MeshOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Mesh) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o MeshOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Mesh) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
func (o MeshOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *Mesh) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly name. The name does not have to be unique and can be changed after creation. Avoid entering confidential information.  Example: `My new resource`
func (o MeshOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Mesh) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o MeshOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Mesh) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
func (o MeshOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Mesh) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// (Updatable) Sets a minimum level of mTLS authentication for all virtual services within the mesh.
func (o MeshOutput) Mtls() MeshMtlsOutput {
	return o.ApplyT(func(v *Mesh) MeshMtlsOutput { return v.Mtls }).(MeshMtlsOutput)
}

// The current state of the Resource.
func (o MeshOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Mesh) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o MeshOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Mesh) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// The time when this resource was created in an RFC3339 formatted datetime string.
func (o MeshOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Mesh) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when this resource was updated in an RFC3339 formatted datetime string.
func (o MeshOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Mesh) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type MeshArrayOutput struct{ *pulumi.OutputState }

func (MeshArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Mesh)(nil)).Elem()
}

func (o MeshArrayOutput) ToMeshArrayOutput() MeshArrayOutput {
	return o
}

func (o MeshArrayOutput) ToMeshArrayOutputWithContext(ctx context.Context) MeshArrayOutput {
	return o
}

func (o MeshArrayOutput) Index(i pulumi.IntInput) MeshOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Mesh {
		return vs[0].([]*Mesh)[vs[1].(int)]
	}).(MeshOutput)
}

type MeshMapOutput struct{ *pulumi.OutputState }

func (MeshMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Mesh)(nil)).Elem()
}

func (o MeshMapOutput) ToMeshMapOutput() MeshMapOutput {
	return o
}

func (o MeshMapOutput) ToMeshMapOutputWithContext(ctx context.Context) MeshMapOutput {
	return o
}

func (o MeshMapOutput) MapIndex(k pulumi.StringInput) MeshOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Mesh {
		return vs[0].(map[string]*Mesh)[vs[1].(string)]
	}).(MeshOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*MeshInput)(nil)).Elem(), &Mesh{})
	pulumi.RegisterInputType(reflect.TypeOf((*MeshArrayInput)(nil)).Elem(), MeshArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*MeshMapInput)(nil)).Elem(), MeshMap{})
	pulumi.RegisterOutputType(MeshOutput{})
	pulumi.RegisterOutputType(MeshArrayOutput{})
	pulumi.RegisterOutputType(MeshMapOutput{})
}