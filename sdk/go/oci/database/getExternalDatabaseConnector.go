// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific External Database Connector resource in Oracle Cloud Infrastructure Database service.
//
// Gets information about the specified external database connector.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.GetExternalDatabaseConnector(ctx, &database.GetExternalDatabaseConnectorArgs{
//				ExternalDatabaseConnectorId: testExternalDatabaseConnectorOciDatabaseExternalDatabaseConnector.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupExternalDatabaseConnector(ctx *pulumi.Context, args *LookupExternalDatabaseConnectorArgs, opts ...pulumi.InvokeOption) (*LookupExternalDatabaseConnectorResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupExternalDatabaseConnectorResult
	err := ctx.Invoke("oci:Database/getExternalDatabaseConnector:getExternalDatabaseConnector", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getExternalDatabaseConnector.
type LookupExternalDatabaseConnectorArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database connector resource (`ExternalDatabaseConnectorId`).
	ExternalDatabaseConnectorId string `pulumi:"externalDatabaseConnectorId"`
}

// A collection of values returned by getExternalDatabaseConnector.
type LookupExternalDatabaseConnectorResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
	ConnectionCredentials []GetExternalDatabaseConnectorConnectionCredential `pulumi:"connectionCredentials"`
	// The status of connectivity to the external database.
	ConnectionStatus string `pulumi:"connectionStatus"`
	// The Oracle Database connection string.
	ConnectionStrings []GetExternalDatabaseConnectorConnectionString `pulumi:"connectionStrings"`
	// The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ConnectorAgentId string `pulumi:"connectorAgentId"`
	// The type of connector used by the external database resource.
	ConnectorType string `pulumi:"connectorType"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
	DisplayName                 string `pulumi:"displayName"`
	ExternalDatabaseConnectorId string `pulumi:"externalDatabaseConnectorId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
	ExternalDatabaseId string `pulumi:"externalDatabaseId"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	Id string `pulumi:"id"`
	// Additional information about the current lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The current lifecycle state of the external database connector resource.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the `connectionStatus` of this external connector was last updated.
	TimeConnectionStatusLastUpdated string `pulumi:"timeConnectionStatusLastUpdated"`
	// The date and time the external connector was created.
	TimeCreated string `pulumi:"timeCreated"`
}

func LookupExternalDatabaseConnectorOutput(ctx *pulumi.Context, args LookupExternalDatabaseConnectorOutputArgs, opts ...pulumi.InvokeOption) LookupExternalDatabaseConnectorResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupExternalDatabaseConnectorResultOutput, error) {
			args := v.(LookupExternalDatabaseConnectorArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getExternalDatabaseConnector:getExternalDatabaseConnector", args, LookupExternalDatabaseConnectorResultOutput{}, options).(LookupExternalDatabaseConnectorResultOutput), nil
		}).(LookupExternalDatabaseConnectorResultOutput)
}

// A collection of arguments for invoking getExternalDatabaseConnector.
type LookupExternalDatabaseConnectorOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database connector resource (`ExternalDatabaseConnectorId`).
	ExternalDatabaseConnectorId pulumi.StringInput `pulumi:"externalDatabaseConnectorId"`
}

func (LookupExternalDatabaseConnectorOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupExternalDatabaseConnectorArgs)(nil)).Elem()
}

// A collection of values returned by getExternalDatabaseConnector.
type LookupExternalDatabaseConnectorResultOutput struct{ *pulumi.OutputState }

func (LookupExternalDatabaseConnectorResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupExternalDatabaseConnectorResult)(nil)).Elem()
}

func (o LookupExternalDatabaseConnectorResultOutput) ToLookupExternalDatabaseConnectorResultOutput() LookupExternalDatabaseConnectorResultOutput {
	return o
}

func (o LookupExternalDatabaseConnectorResultOutput) ToLookupExternalDatabaseConnectorResultOutputWithContext(ctx context.Context) LookupExternalDatabaseConnectorResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupExternalDatabaseConnectorResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Credentials used to connect to the database. Currently only the `DETAILS` type is supported for creating MACS connector crendentials.
func (o LookupExternalDatabaseConnectorResultOutput) ConnectionCredentials() GetExternalDatabaseConnectorConnectionCredentialArrayOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) []GetExternalDatabaseConnectorConnectionCredential {
		return v.ConnectionCredentials
	}).(GetExternalDatabaseConnectorConnectionCredentialArrayOutput)
}

// The status of connectivity to the external database.
func (o LookupExternalDatabaseConnectorResultOutput) ConnectionStatus() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.ConnectionStatus }).(pulumi.StringOutput)
}

// The Oracle Database connection string.
func (o LookupExternalDatabaseConnectorResultOutput) ConnectionStrings() GetExternalDatabaseConnectorConnectionStringArrayOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) []GetExternalDatabaseConnectorConnectionString {
		return v.ConnectionStrings
	}).(GetExternalDatabaseConnectorConnectionStringArrayOutput)
}

// The ID of the agent used for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
func (o LookupExternalDatabaseConnectorResultOutput) ConnectorAgentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.ConnectorAgentId }).(pulumi.StringOutput)
}

// The type of connector used by the external database resource.
func (o LookupExternalDatabaseConnectorResultOutput) ConnectorType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.ConnectorType }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupExternalDatabaseConnectorResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The user-friendly name for the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails). The name does not have to be unique.
func (o LookupExternalDatabaseConnectorResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

func (o LookupExternalDatabaseConnectorResultOutput) ExternalDatabaseConnectorId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.ExternalDatabaseConnectorId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database resource.
func (o LookupExternalDatabaseConnectorResultOutput) ExternalDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.ExternalDatabaseId }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupExternalDatabaseConnectorResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
func (o LookupExternalDatabaseConnectorResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.Id }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state.
func (o LookupExternalDatabaseConnectorResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The current lifecycle state of the external database connector resource.
func (o LookupExternalDatabaseConnectorResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupExternalDatabaseConnectorResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the `connectionStatus` of this external connector was last updated.
func (o LookupExternalDatabaseConnectorResultOutput) TimeConnectionStatusLastUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.TimeConnectionStatusLastUpdated }).(pulumi.StringOutput)
}

// The date and time the external connector was created.
func (o LookupExternalDatabaseConnectorResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupExternalDatabaseConnectorResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupExternalDatabaseConnectorResultOutput{})
}
