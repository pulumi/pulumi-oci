// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of External Databases in Oracle Cloud Infrastructure Database Management service.
//
// Lists the external databases in the specified compartment or in the specified DB system.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasemanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasemanagement.GetExternalDatabases(ctx, &databasemanagement.GetExternalDatabasesArgs{
//				CompartmentId:      pulumi.StringRef(compartmentId),
//				DisplayName:        pulumi.StringRef(externalDatabaseDisplayName),
//				ExternalDatabaseId: pulumi.StringRef(testExternalDatabase.Id),
//				ExternalDbSystemId: pulumi.StringRef(testExternalDbSystem.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetExternalDatabases(ctx *pulumi.Context, args *GetExternalDatabasesArgs, opts ...pulumi.InvokeOption) (*GetExternalDatabasesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetExternalDatabasesResult
	err := ctx.Invoke("oci:DatabaseManagement/getExternalDatabases:getExternalDatabases", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getExternalDatabases.
type GetExternalDatabasesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to only return the resources that match the entire display name.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database.
	ExternalDatabaseId *string `pulumi:"externalDatabaseId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
	ExternalDbSystemId *string                      `pulumi:"externalDbSystemId"`
	Filters            []GetExternalDatabasesFilter `pulumi:"filters"`
}

// A collection of values returned by getExternalDatabases.
type GetExternalDatabasesResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The user-friendly name for the database. The name does not have to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The list of external_database_collection.
	ExternalDatabaseCollections []GetExternalDatabasesExternalDatabaseCollection `pulumi:"externalDatabaseCollections"`
	ExternalDatabaseId          *string                                          `pulumi:"externalDatabaseId"`
	ExternalDbSystemId          *string                                          `pulumi:"externalDbSystemId"`
	Filters                     []GetExternalDatabasesFilter                     `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetExternalDatabasesOutput(ctx *pulumi.Context, args GetExternalDatabasesOutputArgs, opts ...pulumi.InvokeOption) GetExternalDatabasesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetExternalDatabasesResultOutput, error) {
			args := v.(GetExternalDatabasesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DatabaseManagement/getExternalDatabases:getExternalDatabases", args, GetExternalDatabasesResultOutput{}, options).(GetExternalDatabasesResultOutput), nil
		}).(GetExternalDatabasesResultOutput)
}

// A collection of arguments for invoking getExternalDatabases.
type GetExternalDatabasesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to only return the resources that match the entire display name.
	DisplayName pulumi.StringPtrInput `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database.
	ExternalDatabaseId pulumi.StringPtrInput `pulumi:"externalDatabaseId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
	ExternalDbSystemId pulumi.StringPtrInput                `pulumi:"externalDbSystemId"`
	Filters            GetExternalDatabasesFilterArrayInput `pulumi:"filters"`
}

func (GetExternalDatabasesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetExternalDatabasesArgs)(nil)).Elem()
}

// A collection of values returned by getExternalDatabases.
type GetExternalDatabasesResultOutput struct{ *pulumi.OutputState }

func (GetExternalDatabasesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetExternalDatabasesResult)(nil)).Elem()
}

func (o GetExternalDatabasesResultOutput) ToGetExternalDatabasesResultOutput() GetExternalDatabasesResultOutput {
	return o
}

func (o GetExternalDatabasesResultOutput) ToGetExternalDatabasesResultOutputWithContext(ctx context.Context) GetExternalDatabasesResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetExternalDatabasesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExternalDatabasesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The user-friendly name for the database. The name does not have to be unique.
func (o GetExternalDatabasesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExternalDatabasesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// The list of external_database_collection.
func (o GetExternalDatabasesResultOutput) ExternalDatabaseCollections() GetExternalDatabasesExternalDatabaseCollectionArrayOutput {
	return o.ApplyT(func(v GetExternalDatabasesResult) []GetExternalDatabasesExternalDatabaseCollection {
		return v.ExternalDatabaseCollections
	}).(GetExternalDatabasesExternalDatabaseCollectionArrayOutput)
}

func (o GetExternalDatabasesResultOutput) ExternalDatabaseId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExternalDatabasesResult) *string { return v.ExternalDatabaseId }).(pulumi.StringPtrOutput)
}

func (o GetExternalDatabasesResultOutput) ExternalDbSystemId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExternalDatabasesResult) *string { return v.ExternalDbSystemId }).(pulumi.StringPtrOutput)
}

func (o GetExternalDatabasesResultOutput) Filters() GetExternalDatabasesFilterArrayOutput {
	return o.ApplyT(func(v GetExternalDatabasesResult) []GetExternalDatabasesFilter { return v.Filters }).(GetExternalDatabasesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetExternalDatabasesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetExternalDatabasesResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetExternalDatabasesResultOutput{})
}
