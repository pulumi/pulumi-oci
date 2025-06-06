// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Target Database resource in Oracle Cloud Infrastructure Data Safe service.
//
// Returns the details of the specified Data Safe target database.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetTargetDatabase(ctx, &datasafe.GetTargetDatabaseArgs{
//				TargetDatabaseId: testTargetDatabaseOciDataSafeTargetDatabase.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupTargetDatabase(ctx *pulumi.Context, args *LookupTargetDatabaseArgs, opts ...pulumi.InvokeOption) (*LookupTargetDatabaseResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupTargetDatabaseResult
	err := ctx.Invoke("oci:DataSafe/getTargetDatabase:getTargetDatabase", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getTargetDatabase.
type LookupTargetDatabaseArgs struct {
	// The OCID of the Data Safe target database.
	TargetDatabaseId string `pulumi:"targetDatabaseId"`
}

// A collection of values returned by getTargetDatabase.
type LookupTargetDatabaseResult struct {
	// The OCIDs of associated resources like database, Data Safe private endpoint etc.
	AssociatedResourceIds []string `pulumi:"associatedResourceIds"`
	// The OCID of the compartment which contains the Data Safe target database.
	CompartmentId string `pulumi:"compartmentId"`
	// Types of connection supported by Data Safe.
	ConnectionOptions []GetTargetDatabaseConnectionOption `pulumi:"connectionOptions"`
	// The database credentials required for Data Safe to connect to the database.
	Credentials []GetTargetDatabaseCredential `pulumi:"credentials"`
	// Details of the database for the registration in Data Safe.
	DatabaseDetails []GetTargetDatabaseDatabaseDetail `pulumi:"databaseDetails"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The description of the peer target database in Data Safe.
	Description string `pulumi:"description"`
	// The display name of the peer target database in Data Safe.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the Data Safe target database.
	Id string `pulumi:"id"`
	// Details about the current state of the peer target database in Data Safe.
	LifecycleDetails          string                                      `pulumi:"lifecycleDetails"`
	PeerTargetDatabaseDetails []GetTargetDatabasePeerTargetDatabaseDetail `pulumi:"peerTargetDatabaseDetails"`
	// The OCIDs of associated resources like Database, Data Safe private endpoint etc.
	PeerTargetDatabases []GetTargetDatabasePeerTargetDatabaseType `pulumi:"peerTargetDatabases"`
	// The current state of the target database in Data Safe.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags       map[string]string `pulumi:"systemTags"`
	TargetDatabaseId string            `pulumi:"targetDatabaseId"`
	// The date and time the database was registered in Data Safe and created as a target database in Data Safe.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time of the target database update in Data Safe.
	TimeUpdated string `pulumi:"timeUpdated"`
	// The details required to establish a TLS enabled connection.
	TlsConfigs []GetTargetDatabaseTlsConfig `pulumi:"tlsConfigs"`
}

func LookupTargetDatabaseOutput(ctx *pulumi.Context, args LookupTargetDatabaseOutputArgs, opts ...pulumi.InvokeOption) LookupTargetDatabaseResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupTargetDatabaseResultOutput, error) {
			args := v.(LookupTargetDatabaseArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getTargetDatabase:getTargetDatabase", args, LookupTargetDatabaseResultOutput{}, options).(LookupTargetDatabaseResultOutput), nil
		}).(LookupTargetDatabaseResultOutput)
}

// A collection of arguments for invoking getTargetDatabase.
type LookupTargetDatabaseOutputArgs struct {
	// The OCID of the Data Safe target database.
	TargetDatabaseId pulumi.StringInput `pulumi:"targetDatabaseId"`
}

func (LookupTargetDatabaseOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupTargetDatabaseArgs)(nil)).Elem()
}

// A collection of values returned by getTargetDatabase.
type LookupTargetDatabaseResultOutput struct{ *pulumi.OutputState }

func (LookupTargetDatabaseResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupTargetDatabaseResult)(nil)).Elem()
}

func (o LookupTargetDatabaseResultOutput) ToLookupTargetDatabaseResultOutput() LookupTargetDatabaseResultOutput {
	return o
}

func (o LookupTargetDatabaseResultOutput) ToLookupTargetDatabaseResultOutputWithContext(ctx context.Context) LookupTargetDatabaseResultOutput {
	return o
}

// The OCIDs of associated resources like database, Data Safe private endpoint etc.
func (o LookupTargetDatabaseResultOutput) AssociatedResourceIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) []string { return v.AssociatedResourceIds }).(pulumi.StringArrayOutput)
}

// The OCID of the compartment which contains the Data Safe target database.
func (o LookupTargetDatabaseResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Types of connection supported by Data Safe.
func (o LookupTargetDatabaseResultOutput) ConnectionOptions() GetTargetDatabaseConnectionOptionArrayOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) []GetTargetDatabaseConnectionOption { return v.ConnectionOptions }).(GetTargetDatabaseConnectionOptionArrayOutput)
}

// The database credentials required for Data Safe to connect to the database.
func (o LookupTargetDatabaseResultOutput) Credentials() GetTargetDatabaseCredentialArrayOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) []GetTargetDatabaseCredential { return v.Credentials }).(GetTargetDatabaseCredentialArrayOutput)
}

// Details of the database for the registration in Data Safe.
func (o LookupTargetDatabaseResultOutput) DatabaseDetails() GetTargetDatabaseDatabaseDetailArrayOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) []GetTargetDatabaseDatabaseDetail { return v.DatabaseDetails }).(GetTargetDatabaseDatabaseDetailArrayOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
func (o LookupTargetDatabaseResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The description of the peer target database in Data Safe.
func (o LookupTargetDatabaseResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the peer target database in Data Safe.
func (o LookupTargetDatabaseResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o LookupTargetDatabaseResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the Data Safe target database.
func (o LookupTargetDatabaseResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) string { return v.Id }).(pulumi.StringOutput)
}

// Details about the current state of the peer target database in Data Safe.
func (o LookupTargetDatabaseResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o LookupTargetDatabaseResultOutput) PeerTargetDatabaseDetails() GetTargetDatabasePeerTargetDatabaseDetailArrayOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) []GetTargetDatabasePeerTargetDatabaseDetail {
		return v.PeerTargetDatabaseDetails
	}).(GetTargetDatabasePeerTargetDatabaseDetailArrayOutput)
}

// The OCIDs of associated resources like Database, Data Safe private endpoint etc.
func (o LookupTargetDatabaseResultOutput) PeerTargetDatabases() GetTargetDatabasePeerTargetDatabaseTypeArrayOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) []GetTargetDatabasePeerTargetDatabaseType {
		return v.PeerTargetDatabases
	}).(GetTargetDatabasePeerTargetDatabaseTypeArrayOutput)
}

// The current state of the target database in Data Safe.
func (o LookupTargetDatabaseResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupTargetDatabaseResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

func (o LookupTargetDatabaseResultOutput) TargetDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) string { return v.TargetDatabaseId }).(pulumi.StringOutput)
}

// The date and time the database was registered in Data Safe and created as a target database in Data Safe.
func (o LookupTargetDatabaseResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time of the target database update in Data Safe.
func (o LookupTargetDatabaseResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The details required to establish a TLS enabled connection.
func (o LookupTargetDatabaseResultOutput) TlsConfigs() GetTargetDatabaseTlsConfigArrayOutput {
	return o.ApplyT(func(v LookupTargetDatabaseResult) []GetTargetDatabaseTlsConfig { return v.TlsConfigs }).(GetTargetDatabaseTlsConfigArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupTargetDatabaseResultOutput{})
}
