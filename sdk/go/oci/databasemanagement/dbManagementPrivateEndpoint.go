// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Db Management Private Endpoint resource in Oracle Cloud Infrastructure Database Management service.
//
// Creates a new Database Management private endpoint.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DatabaseManagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DatabaseManagement.NewDbManagementPrivateEndpoint(ctx, "testDbManagementPrivateEndpoint", &DatabaseManagement.DbManagementPrivateEndpointArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				SubnetId:      pulumi.Any(oci_core_subnet.Test_subnet.Id),
//				Description:   pulumi.Any(_var.Db_management_private_endpoint_description),
//				IsCluster:     pulumi.Any(_var.Db_management_private_endpoint_is_cluster),
//				NsgIds:        pulumi.Any(_var.Db_management_private_endpoint_nsg_ids),
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
// DbManagementPrivateEndpoints can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:DatabaseManagement/dbManagementPrivateEndpoint:DbManagementPrivateEndpoint test_db_management_private_endpoint "id"
//
// ```
type DbManagementPrivateEndpoint struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The description of the private endpoint.
	Description pulumi.StringOutput `pulumi:"description"`
	// Specifies whether the Database Management private endpoint will be used for Oracle Databases in a cluster.
	IsCluster pulumi.BoolOutput `pulumi:"isCluster"`
	// (Updatable) The display name of the Database Management private endpoint.
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
	NsgIds pulumi.StringArrayOutput `pulumi:"nsgIds"`
	// The IP addresses assigned to the Database Management private endpoint.
	PrivateIp pulumi.StringOutput `pulumi:"privateIp"`
	// The current lifecycle state of the Database Management private endpoint.
	State pulumi.StringOutput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// The date and time the Database Managament private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
}

// NewDbManagementPrivateEndpoint registers a new resource with the given unique name, arguments, and options.
func NewDbManagementPrivateEndpoint(ctx *pulumi.Context,
	name string, args *DbManagementPrivateEndpointArgs, opts ...pulumi.ResourceOption) (*DbManagementPrivateEndpoint, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.SubnetId == nil {
		return nil, errors.New("invalid value for required argument 'SubnetId'")
	}
	var resource DbManagementPrivateEndpoint
	err := ctx.RegisterResource("oci:DatabaseManagement/dbManagementPrivateEndpoint:DbManagementPrivateEndpoint", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDbManagementPrivateEndpoint gets an existing DbManagementPrivateEndpoint resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDbManagementPrivateEndpoint(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DbManagementPrivateEndpointState, opts ...pulumi.ResourceOption) (*DbManagementPrivateEndpoint, error) {
	var resource DbManagementPrivateEndpoint
	err := ctx.ReadResource("oci:DatabaseManagement/dbManagementPrivateEndpoint:DbManagementPrivateEndpoint", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DbManagementPrivateEndpoint resources.
type dbManagementPrivateEndpointState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The description of the private endpoint.
	Description *string `pulumi:"description"`
	// Specifies whether the Database Management private endpoint will be used for Oracle Databases in a cluster.
	IsCluster *bool `pulumi:"isCluster"`
	// (Updatable) The display name of the Database Management private endpoint.
	Name *string `pulumi:"name"`
	// (Updatable) The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
	NsgIds []string `pulumi:"nsgIds"`
	// The IP addresses assigned to the Database Management private endpoint.
	PrivateIp *string `pulumi:"privateIp"`
	// The current lifecycle state of the Database Management private endpoint.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
	SubnetId *string `pulumi:"subnetId"`
	// The date and time the Database Managament private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId *string `pulumi:"vcnId"`
}

type DbManagementPrivateEndpointState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The description of the private endpoint.
	Description pulumi.StringPtrInput
	// Specifies whether the Database Management private endpoint will be used for Oracle Databases in a cluster.
	IsCluster pulumi.BoolPtrInput
	// (Updatable) The display name of the Database Management private endpoint.
	Name pulumi.StringPtrInput
	// (Updatable) The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
	NsgIds pulumi.StringArrayInput
	// The IP addresses assigned to the Database Management private endpoint.
	PrivateIp pulumi.StringPtrInput
	// The current lifecycle state of the Database Management private endpoint.
	State pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
	SubnetId pulumi.StringPtrInput
	// The date and time the Database Managament private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
	VcnId pulumi.StringPtrInput
}

func (DbManagementPrivateEndpointState) ElementType() reflect.Type {
	return reflect.TypeOf((*dbManagementPrivateEndpointState)(nil)).Elem()
}

type dbManagementPrivateEndpointArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The description of the private endpoint.
	Description *string `pulumi:"description"`
	// Specifies whether the Database Management private endpoint will be used for Oracle Databases in a cluster.
	IsCluster *bool `pulumi:"isCluster"`
	// (Updatable) The display name of the Database Management private endpoint.
	Name *string `pulumi:"name"`
	// (Updatable) The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
	NsgIds []string `pulumi:"nsgIds"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
	SubnetId string `pulumi:"subnetId"`
}

// The set of arguments for constructing a DbManagementPrivateEndpoint resource.
type DbManagementPrivateEndpointArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) The description of the private endpoint.
	Description pulumi.StringPtrInput
	// Specifies whether the Database Management private endpoint will be used for Oracle Databases in a cluster.
	IsCluster pulumi.BoolPtrInput
	// (Updatable) The display name of the Database Management private endpoint.
	Name pulumi.StringPtrInput
	// (Updatable) The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
	NsgIds pulumi.StringArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
	SubnetId pulumi.StringInput
}

func (DbManagementPrivateEndpointArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*dbManagementPrivateEndpointArgs)(nil)).Elem()
}

type DbManagementPrivateEndpointInput interface {
	pulumi.Input

	ToDbManagementPrivateEndpointOutput() DbManagementPrivateEndpointOutput
	ToDbManagementPrivateEndpointOutputWithContext(ctx context.Context) DbManagementPrivateEndpointOutput
}

func (*DbManagementPrivateEndpoint) ElementType() reflect.Type {
	return reflect.TypeOf((**DbManagementPrivateEndpoint)(nil)).Elem()
}

func (i *DbManagementPrivateEndpoint) ToDbManagementPrivateEndpointOutput() DbManagementPrivateEndpointOutput {
	return i.ToDbManagementPrivateEndpointOutputWithContext(context.Background())
}

func (i *DbManagementPrivateEndpoint) ToDbManagementPrivateEndpointOutputWithContext(ctx context.Context) DbManagementPrivateEndpointOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DbManagementPrivateEndpointOutput)
}

// DbManagementPrivateEndpointArrayInput is an input type that accepts DbManagementPrivateEndpointArray and DbManagementPrivateEndpointArrayOutput values.
// You can construct a concrete instance of `DbManagementPrivateEndpointArrayInput` via:
//
//	DbManagementPrivateEndpointArray{ DbManagementPrivateEndpointArgs{...} }
type DbManagementPrivateEndpointArrayInput interface {
	pulumi.Input

	ToDbManagementPrivateEndpointArrayOutput() DbManagementPrivateEndpointArrayOutput
	ToDbManagementPrivateEndpointArrayOutputWithContext(context.Context) DbManagementPrivateEndpointArrayOutput
}

type DbManagementPrivateEndpointArray []DbManagementPrivateEndpointInput

func (DbManagementPrivateEndpointArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DbManagementPrivateEndpoint)(nil)).Elem()
}

func (i DbManagementPrivateEndpointArray) ToDbManagementPrivateEndpointArrayOutput() DbManagementPrivateEndpointArrayOutput {
	return i.ToDbManagementPrivateEndpointArrayOutputWithContext(context.Background())
}

func (i DbManagementPrivateEndpointArray) ToDbManagementPrivateEndpointArrayOutputWithContext(ctx context.Context) DbManagementPrivateEndpointArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DbManagementPrivateEndpointArrayOutput)
}

// DbManagementPrivateEndpointMapInput is an input type that accepts DbManagementPrivateEndpointMap and DbManagementPrivateEndpointMapOutput values.
// You can construct a concrete instance of `DbManagementPrivateEndpointMapInput` via:
//
//	DbManagementPrivateEndpointMap{ "key": DbManagementPrivateEndpointArgs{...} }
type DbManagementPrivateEndpointMapInput interface {
	pulumi.Input

	ToDbManagementPrivateEndpointMapOutput() DbManagementPrivateEndpointMapOutput
	ToDbManagementPrivateEndpointMapOutputWithContext(context.Context) DbManagementPrivateEndpointMapOutput
}

type DbManagementPrivateEndpointMap map[string]DbManagementPrivateEndpointInput

func (DbManagementPrivateEndpointMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DbManagementPrivateEndpoint)(nil)).Elem()
}

func (i DbManagementPrivateEndpointMap) ToDbManagementPrivateEndpointMapOutput() DbManagementPrivateEndpointMapOutput {
	return i.ToDbManagementPrivateEndpointMapOutputWithContext(context.Background())
}

func (i DbManagementPrivateEndpointMap) ToDbManagementPrivateEndpointMapOutputWithContext(ctx context.Context) DbManagementPrivateEndpointMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DbManagementPrivateEndpointMapOutput)
}

type DbManagementPrivateEndpointOutput struct{ *pulumi.OutputState }

func (DbManagementPrivateEndpointOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DbManagementPrivateEndpoint)(nil)).Elem()
}

func (o DbManagementPrivateEndpointOutput) ToDbManagementPrivateEndpointOutput() DbManagementPrivateEndpointOutput {
	return o
}

func (o DbManagementPrivateEndpointOutput) ToDbManagementPrivateEndpointOutputWithContext(ctx context.Context) DbManagementPrivateEndpointOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o DbManagementPrivateEndpointOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The description of the private endpoint.
func (o DbManagementPrivateEndpointOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// Specifies whether the Database Management private endpoint will be used for Oracle Databases in a cluster.
func (o DbManagementPrivateEndpointOutput) IsCluster() pulumi.BoolOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.BoolOutput { return v.IsCluster }).(pulumi.BoolOutput)
}

// (Updatable) The display name of the Database Management private endpoint.
func (o DbManagementPrivateEndpointOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// (Updatable) The OCIDs of the Network Security Groups to which the Database Management private endpoint belongs.
func (o DbManagementPrivateEndpointOutput) NsgIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.StringArrayOutput { return v.NsgIds }).(pulumi.StringArrayOutput)
}

// The IP addresses assigned to the Database Management private endpoint.
func (o DbManagementPrivateEndpointOutput) PrivateIp() pulumi.StringOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.StringOutput { return v.PrivateIp }).(pulumi.StringOutput)
}

// The current lifecycle state of the Database Management private endpoint.
func (o DbManagementPrivateEndpointOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet.
func (o DbManagementPrivateEndpointOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.StringOutput { return v.SubnetId }).(pulumi.StringOutput)
}

// The date and time the Database Managament private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o DbManagementPrivateEndpointOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
func (o DbManagementPrivateEndpointOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v *DbManagementPrivateEndpoint) pulumi.StringOutput { return v.VcnId }).(pulumi.StringOutput)
}

type DbManagementPrivateEndpointArrayOutput struct{ *pulumi.OutputState }

func (DbManagementPrivateEndpointArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DbManagementPrivateEndpoint)(nil)).Elem()
}

func (o DbManagementPrivateEndpointArrayOutput) ToDbManagementPrivateEndpointArrayOutput() DbManagementPrivateEndpointArrayOutput {
	return o
}

func (o DbManagementPrivateEndpointArrayOutput) ToDbManagementPrivateEndpointArrayOutputWithContext(ctx context.Context) DbManagementPrivateEndpointArrayOutput {
	return o
}

func (o DbManagementPrivateEndpointArrayOutput) Index(i pulumi.IntInput) DbManagementPrivateEndpointOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DbManagementPrivateEndpoint {
		return vs[0].([]*DbManagementPrivateEndpoint)[vs[1].(int)]
	}).(DbManagementPrivateEndpointOutput)
}

type DbManagementPrivateEndpointMapOutput struct{ *pulumi.OutputState }

func (DbManagementPrivateEndpointMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DbManagementPrivateEndpoint)(nil)).Elem()
}

func (o DbManagementPrivateEndpointMapOutput) ToDbManagementPrivateEndpointMapOutput() DbManagementPrivateEndpointMapOutput {
	return o
}

func (o DbManagementPrivateEndpointMapOutput) ToDbManagementPrivateEndpointMapOutputWithContext(ctx context.Context) DbManagementPrivateEndpointMapOutput {
	return o
}

func (o DbManagementPrivateEndpointMapOutput) MapIndex(k pulumi.StringInput) DbManagementPrivateEndpointOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DbManagementPrivateEndpoint {
		return vs[0].(map[string]*DbManagementPrivateEndpoint)[vs[1].(string)]
	}).(DbManagementPrivateEndpointOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DbManagementPrivateEndpointInput)(nil)).Elem(), &DbManagementPrivateEndpoint{})
	pulumi.RegisterInputType(reflect.TypeOf((*DbManagementPrivateEndpointArrayInput)(nil)).Elem(), DbManagementPrivateEndpointArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DbManagementPrivateEndpointMapInput)(nil)).Elem(), DbManagementPrivateEndpointMap{})
	pulumi.RegisterOutputType(DbManagementPrivateEndpointOutput{})
	pulumi.RegisterOutputType(DbManagementPrivateEndpointArrayOutput{})
	pulumi.RegisterOutputType(DbManagementPrivateEndpointMapOutput{})
}