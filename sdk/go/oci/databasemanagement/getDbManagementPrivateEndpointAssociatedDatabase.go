// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Db Management Private Endpoint Associated Database resource in Oracle Cloud Infrastructure Database Management service.
//
// Gets the list of databases using a specific Database Management private endpoint.
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
//			_, err := DatabaseManagement.GetDbManagementPrivateEndpointAssociatedDatabase(ctx, &databasemanagement.GetDbManagementPrivateEndpointAssociatedDatabaseArgs{
//				CompartmentId:                 _var.Compartment_id,
//				DbManagementPrivateEndpointId: oci_database_management_db_management_private_endpoint.Test_db_management_private_endpoint.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDbManagementPrivateEndpointAssociatedDatabase(ctx *pulumi.Context, args *GetDbManagementPrivateEndpointAssociatedDatabaseArgs, opts ...pulumi.InvokeOption) (*GetDbManagementPrivateEndpointAssociatedDatabaseResult, error) {
	var rv GetDbManagementPrivateEndpointAssociatedDatabaseResult
	err := ctx.Invoke("oci:DatabaseManagement/getDbManagementPrivateEndpointAssociatedDatabase:getDbManagementPrivateEndpointAssociatedDatabase", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbManagementPrivateEndpointAssociatedDatabase.
type GetDbManagementPrivateEndpointAssociatedDatabaseArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
	DbManagementPrivateEndpointId string `pulumi:"dbManagementPrivateEndpointId"`
}

// A collection of values returned by getDbManagementPrivateEndpointAssociatedDatabase.
type GetDbManagementPrivateEndpointAssociatedDatabaseResult struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
	CompartmentId                 string `pulumi:"compartmentId"`
	DbManagementPrivateEndpointId string `pulumi:"dbManagementPrivateEndpointId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// A list of databases using a Database Management private endpoint.
	Items []GetDbManagementPrivateEndpointAssociatedDatabaseItem `pulumi:"items"`
}

func GetDbManagementPrivateEndpointAssociatedDatabaseOutput(ctx *pulumi.Context, args GetDbManagementPrivateEndpointAssociatedDatabaseOutputArgs, opts ...pulumi.InvokeOption) GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDbManagementPrivateEndpointAssociatedDatabaseResult, error) {
			args := v.(GetDbManagementPrivateEndpointAssociatedDatabaseArgs)
			r, err := GetDbManagementPrivateEndpointAssociatedDatabase(ctx, &args, opts...)
			var s GetDbManagementPrivateEndpointAssociatedDatabaseResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput)
}

// A collection of arguments for invoking getDbManagementPrivateEndpointAssociatedDatabase.
type GetDbManagementPrivateEndpointAssociatedDatabaseOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Management private endpoint.
	DbManagementPrivateEndpointId pulumi.StringInput `pulumi:"dbManagementPrivateEndpointId"`
}

func (GetDbManagementPrivateEndpointAssociatedDatabaseOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbManagementPrivateEndpointAssociatedDatabaseArgs)(nil)).Elem()
}

// A collection of values returned by getDbManagementPrivateEndpointAssociatedDatabase.
type GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput struct{ *pulumi.OutputState }

func (GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbManagementPrivateEndpointAssociatedDatabaseResult)(nil)).Elem()
}

func (o GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput) ToGetDbManagementPrivateEndpointAssociatedDatabaseResultOutput() GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput {
	return o
}

func (o GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput) ToGetDbManagementPrivateEndpointAssociatedDatabaseResultOutputWithContext(ctx context.Context) GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput {
	return o
}

// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
func (o GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbManagementPrivateEndpointAssociatedDatabaseResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput) DbManagementPrivateEndpointId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbManagementPrivateEndpointAssociatedDatabaseResult) string {
		return v.DbManagementPrivateEndpointId
	}).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbManagementPrivateEndpointAssociatedDatabaseResult) string { return v.Id }).(pulumi.StringOutput)
}

// A list of databases using a Database Management private endpoint.
func (o GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput) Items() GetDbManagementPrivateEndpointAssociatedDatabaseItemArrayOutput {
	return o.ApplyT(func(v GetDbManagementPrivateEndpointAssociatedDatabaseResult) []GetDbManagementPrivateEndpointAssociatedDatabaseItem {
		return v.Items
	}).(GetDbManagementPrivateEndpointAssociatedDatabaseItemArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDbManagementPrivateEndpointAssociatedDatabaseResultOutput{})
}