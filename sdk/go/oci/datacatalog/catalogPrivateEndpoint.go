// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datacatalog

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Catalog Private Endpoint resource in Oracle Cloud Infrastructure Data Catalog service.
//
// Create a new private reverse connection endpoint.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datacatalog"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datacatalog.NewCatalogPrivateEndpoint(ctx, "test_catalog_private_endpoint", &datacatalog.CatalogPrivateEndpointArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				DnsZones:      pulumi.Any(catalogPrivateEndpointDnsZones),
//				SubnetId:      pulumi.Any(testSubnet.Id),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				DisplayName: pulumi.Any(catalogPrivateEndpointDisplayName),
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
// CatalogPrivateEndpoints can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataCatalog/catalogPrivateEndpoint:CatalogPrivateEndpoint test_catalog_private_endpoint "id"
// ```
type CatalogPrivateEndpoint struct {
	pulumi.CustomResourceState

	// The list of catalogs using the private reverse connection endpoint
	AttachedCatalogs pulumi.StringArrayOutput `pulumi:"attachedCatalogs"`
	// (Updatable) Compartment identifier.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones pulumi.StringArrayOutput `pulumi:"dnsZones"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Locks associated with this resource.
	Locks CatalogPrivateEndpointLockArrayOutput `pulumi:"locks"`
	// The current state of the private endpoint resource.
	State pulumi.StringOutput `pulumi:"state"`
	// The OCID of subnet to which the reverse connection is to be created
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewCatalogPrivateEndpoint registers a new resource with the given unique name, arguments, and options.
func NewCatalogPrivateEndpoint(ctx *pulumi.Context,
	name string, args *CatalogPrivateEndpointArgs, opts ...pulumi.ResourceOption) (*CatalogPrivateEndpoint, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DnsZones == nil {
		return nil, errors.New("invalid value for required argument 'DnsZones'")
	}
	if args.SubnetId == nil {
		return nil, errors.New("invalid value for required argument 'SubnetId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource CatalogPrivateEndpoint
	err := ctx.RegisterResource("oci:DataCatalog/catalogPrivateEndpoint:CatalogPrivateEndpoint", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCatalogPrivateEndpoint gets an existing CatalogPrivateEndpoint resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCatalogPrivateEndpoint(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CatalogPrivateEndpointState, opts ...pulumi.ResourceOption) (*CatalogPrivateEndpoint, error) {
	var resource CatalogPrivateEndpoint
	err := ctx.ReadResource("oci:DataCatalog/catalogPrivateEndpoint:CatalogPrivateEndpoint", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CatalogPrivateEndpoint resources.
type catalogPrivateEndpointState struct {
	// The list of catalogs using the private reverse connection endpoint
	AttachedCatalogs []string `pulumi:"attachedCatalogs"`
	// (Updatable) Compartment identifier.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones []string `pulumi:"dnsZones"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Locks associated with this resource.
	Locks []CatalogPrivateEndpointLock `pulumi:"locks"`
	// The current state of the private endpoint resource.
	State *string `pulumi:"state"`
	// The OCID of subnet to which the reverse connection is to be created
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId *string `pulumi:"subnetId"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type CatalogPrivateEndpointState struct {
	// The list of catalogs using the private reverse connection endpoint
	AttachedCatalogs pulumi.StringArrayInput
	// (Updatable) Compartment identifier.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName pulumi.StringPtrInput
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones pulumi.StringArrayInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
	LifecycleDetails pulumi.StringPtrInput
	// Locks associated with this resource.
	Locks CatalogPrivateEndpointLockArrayInput
	// The current state of the private endpoint resource.
	State pulumi.StringPtrInput
	// The OCID of subnet to which the reverse connection is to be created
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (CatalogPrivateEndpointState) ElementType() reflect.Type {
	return reflect.TypeOf((*catalogPrivateEndpointState)(nil)).Elem()
}

type catalogPrivateEndpointArgs struct {
	// (Updatable) Compartment identifier.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones []string `pulumi:"dnsZones"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of subnet to which the reverse connection is to be created
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId string `pulumi:"subnetId"`
}

// The set of arguments for constructing a CatalogPrivateEndpoint resource.
type CatalogPrivateEndpointArgs struct {
	// (Updatable) Compartment identifier.
	CompartmentId pulumi.StringInput
	// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Display name of the private endpoint resource being created.
	DisplayName pulumi.StringPtrInput
	// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
	DnsZones pulumi.StringArrayInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// The OCID of subnet to which the reverse connection is to be created
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId pulumi.StringInput
}

func (CatalogPrivateEndpointArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*catalogPrivateEndpointArgs)(nil)).Elem()
}

type CatalogPrivateEndpointInput interface {
	pulumi.Input

	ToCatalogPrivateEndpointOutput() CatalogPrivateEndpointOutput
	ToCatalogPrivateEndpointOutputWithContext(ctx context.Context) CatalogPrivateEndpointOutput
}

func (*CatalogPrivateEndpoint) ElementType() reflect.Type {
	return reflect.TypeOf((**CatalogPrivateEndpoint)(nil)).Elem()
}

func (i *CatalogPrivateEndpoint) ToCatalogPrivateEndpointOutput() CatalogPrivateEndpointOutput {
	return i.ToCatalogPrivateEndpointOutputWithContext(context.Background())
}

func (i *CatalogPrivateEndpoint) ToCatalogPrivateEndpointOutputWithContext(ctx context.Context) CatalogPrivateEndpointOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CatalogPrivateEndpointOutput)
}

// CatalogPrivateEndpointArrayInput is an input type that accepts CatalogPrivateEndpointArray and CatalogPrivateEndpointArrayOutput values.
// You can construct a concrete instance of `CatalogPrivateEndpointArrayInput` via:
//
//	CatalogPrivateEndpointArray{ CatalogPrivateEndpointArgs{...} }
type CatalogPrivateEndpointArrayInput interface {
	pulumi.Input

	ToCatalogPrivateEndpointArrayOutput() CatalogPrivateEndpointArrayOutput
	ToCatalogPrivateEndpointArrayOutputWithContext(context.Context) CatalogPrivateEndpointArrayOutput
}

type CatalogPrivateEndpointArray []CatalogPrivateEndpointInput

func (CatalogPrivateEndpointArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CatalogPrivateEndpoint)(nil)).Elem()
}

func (i CatalogPrivateEndpointArray) ToCatalogPrivateEndpointArrayOutput() CatalogPrivateEndpointArrayOutput {
	return i.ToCatalogPrivateEndpointArrayOutputWithContext(context.Background())
}

func (i CatalogPrivateEndpointArray) ToCatalogPrivateEndpointArrayOutputWithContext(ctx context.Context) CatalogPrivateEndpointArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CatalogPrivateEndpointArrayOutput)
}

// CatalogPrivateEndpointMapInput is an input type that accepts CatalogPrivateEndpointMap and CatalogPrivateEndpointMapOutput values.
// You can construct a concrete instance of `CatalogPrivateEndpointMapInput` via:
//
//	CatalogPrivateEndpointMap{ "key": CatalogPrivateEndpointArgs{...} }
type CatalogPrivateEndpointMapInput interface {
	pulumi.Input

	ToCatalogPrivateEndpointMapOutput() CatalogPrivateEndpointMapOutput
	ToCatalogPrivateEndpointMapOutputWithContext(context.Context) CatalogPrivateEndpointMapOutput
}

type CatalogPrivateEndpointMap map[string]CatalogPrivateEndpointInput

func (CatalogPrivateEndpointMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CatalogPrivateEndpoint)(nil)).Elem()
}

func (i CatalogPrivateEndpointMap) ToCatalogPrivateEndpointMapOutput() CatalogPrivateEndpointMapOutput {
	return i.ToCatalogPrivateEndpointMapOutputWithContext(context.Background())
}

func (i CatalogPrivateEndpointMap) ToCatalogPrivateEndpointMapOutputWithContext(ctx context.Context) CatalogPrivateEndpointMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CatalogPrivateEndpointMapOutput)
}

type CatalogPrivateEndpointOutput struct{ *pulumi.OutputState }

func (CatalogPrivateEndpointOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CatalogPrivateEndpoint)(nil)).Elem()
}

func (o CatalogPrivateEndpointOutput) ToCatalogPrivateEndpointOutput() CatalogPrivateEndpointOutput {
	return o
}

func (o CatalogPrivateEndpointOutput) ToCatalogPrivateEndpointOutputWithContext(ctx context.Context) CatalogPrivateEndpointOutput {
	return o
}

// The list of catalogs using the private reverse connection endpoint
func (o CatalogPrivateEndpointOutput) AttachedCatalogs() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringArrayOutput { return v.AttachedCatalogs }).(pulumi.StringArrayOutput)
}

// (Updatable) Compartment identifier.
func (o CatalogPrivateEndpointOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
func (o CatalogPrivateEndpointOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Display name of the private endpoint resource being created.
func (o CatalogPrivateEndpointOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) List of DNS zones to be used by the data assets to be harvested. Example: custpvtsubnet.oraclevcn.com for data asset: db.custpvtsubnet.oraclevcn.com
func (o CatalogPrivateEndpointOutput) DnsZones() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringArrayOutput { return v.DnsZones }).(pulumi.StringArrayOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o CatalogPrivateEndpointOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
func (o CatalogPrivateEndpointOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Locks associated with this resource.
func (o CatalogPrivateEndpointOutput) Locks() CatalogPrivateEndpointLockArrayOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) CatalogPrivateEndpointLockArrayOutput { return v.Locks }).(CatalogPrivateEndpointLockArrayOutput)
}

// The current state of the private endpoint resource.
func (o CatalogPrivateEndpointOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The OCID of subnet to which the reverse connection is to be created
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o CatalogPrivateEndpointOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringOutput { return v.SubnetId }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o CatalogPrivateEndpointOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
func (o CatalogPrivateEndpointOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
func (o CatalogPrivateEndpointOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *CatalogPrivateEndpoint) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type CatalogPrivateEndpointArrayOutput struct{ *pulumi.OutputState }

func (CatalogPrivateEndpointArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CatalogPrivateEndpoint)(nil)).Elem()
}

func (o CatalogPrivateEndpointArrayOutput) ToCatalogPrivateEndpointArrayOutput() CatalogPrivateEndpointArrayOutput {
	return o
}

func (o CatalogPrivateEndpointArrayOutput) ToCatalogPrivateEndpointArrayOutputWithContext(ctx context.Context) CatalogPrivateEndpointArrayOutput {
	return o
}

func (o CatalogPrivateEndpointArrayOutput) Index(i pulumi.IntInput) CatalogPrivateEndpointOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *CatalogPrivateEndpoint {
		return vs[0].([]*CatalogPrivateEndpoint)[vs[1].(int)]
	}).(CatalogPrivateEndpointOutput)
}

type CatalogPrivateEndpointMapOutput struct{ *pulumi.OutputState }

func (CatalogPrivateEndpointMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CatalogPrivateEndpoint)(nil)).Elem()
}

func (o CatalogPrivateEndpointMapOutput) ToCatalogPrivateEndpointMapOutput() CatalogPrivateEndpointMapOutput {
	return o
}

func (o CatalogPrivateEndpointMapOutput) ToCatalogPrivateEndpointMapOutputWithContext(ctx context.Context) CatalogPrivateEndpointMapOutput {
	return o
}

func (o CatalogPrivateEndpointMapOutput) MapIndex(k pulumi.StringInput) CatalogPrivateEndpointOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *CatalogPrivateEndpoint {
		return vs[0].(map[string]*CatalogPrivateEndpoint)[vs[1].(string)]
	}).(CatalogPrivateEndpointOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*CatalogPrivateEndpointInput)(nil)).Elem(), &CatalogPrivateEndpoint{})
	pulumi.RegisterInputType(reflect.TypeOf((*CatalogPrivateEndpointArrayInput)(nil)).Elem(), CatalogPrivateEndpointArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*CatalogPrivateEndpointMapInput)(nil)).Elem(), CatalogPrivateEndpointMap{})
	pulumi.RegisterOutputType(CatalogPrivateEndpointOutput{})
	pulumi.RegisterOutputType(CatalogPrivateEndpointArrayOutput{})
	pulumi.RegisterOutputType(CatalogPrivateEndpointMapOutput{})
}
