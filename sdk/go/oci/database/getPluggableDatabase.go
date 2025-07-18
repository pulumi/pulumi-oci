// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Pluggable Database resource in Oracle Cloud Infrastructure Database service.
//
// Gets information about the specified pluggable database.
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
//			_, err := database.GetPluggableDatabase(ctx, &database.GetPluggableDatabaseArgs{
//				PluggableDatabaseId: testPluggableDatabaseOciDatabasePluggableDatabase.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupPluggableDatabase(ctx *pulumi.Context, args *LookupPluggableDatabaseArgs, opts ...pulumi.InvokeOption) (*LookupPluggableDatabaseResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupPluggableDatabaseResult
	err := ctx.Invoke("oci:Database/getPluggableDatabase:getPluggableDatabase", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPluggableDatabase.
type LookupPluggableDatabaseArgs struct {
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId string `pulumi:"pluggableDatabaseId"`
}

// A collection of values returned by getPluggableDatabase.
type LookupPluggableDatabaseResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Connection strings to connect to an Oracle Pluggable Database.
	ConnectionStrings              []GetPluggableDatabaseConnectionString `pulumi:"connectionStrings"`
	ContainerDatabaseAdminPassword string                                 `pulumi:"containerDatabaseAdminPassword"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
	ContainerDatabaseId     string `pulumi:"containerDatabaseId"`
	ConvertToRegularTrigger int    `pulumi:"convertToRegularTrigger"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pluggable database.
	Id string `pulumi:"id"`
	// The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
	IsRestricted    bool   `pulumi:"isRestricted"`
	KmsKeyVersionId string `pulumi:"kmsKeyVersionId"`
	// Detailed message for the lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
	OpenMode               string                                      `pulumi:"openMode"`
	PdbAdminPassword       string                                      `pulumi:"pdbAdminPassword"`
	PdbCreationTypeDetails []GetPluggableDatabasePdbCreationTypeDetail `pulumi:"pdbCreationTypeDetails"`
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	PdbName string `pulumi:"pdbName"`
	// Pluggable Database Node Level Details. Example: [{"nodeName" : "node1", "openMode" : "READ_WRITE"}, {"nodeName" : "node2", "openMode" : "READ_ONLY"}]
	PdbNodeLevelDetails []GetPluggableDatabasePdbNodeLevelDetail `pulumi:"pdbNodeLevelDetails"`
	PluggableDatabaseId string                                   `pulumi:"pluggableDatabaseId"`
	// The configuration of the Pluggable Database Management service.
	PluggableDatabaseManagementConfigs []GetPluggableDatabasePluggableDatabaseManagementConfig `pulumi:"pluggableDatabaseManagementConfigs"`
	RefreshTrigger                     int                                                     `pulumi:"refreshTrigger"`
	// Pluggable Database Refreshable Clone Configuration.
	RefreshableCloneConfigs       []GetPluggableDatabaseRefreshableCloneConfig `pulumi:"refreshableCloneConfigs"`
	RotateKeyTrigger              int                                          `pulumi:"rotateKeyTrigger"`
	ShouldCreatePdbBackup         bool                                         `pulumi:"shouldCreatePdbBackup"`
	ShouldPdbAdminAccountBeLocked bool                                         `pulumi:"shouldPdbAdminAccountBeLocked"`
	// The current state of the pluggable database.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	SystemTags        map[string]string `pulumi:"systemTags"`
	TdeWalletPassword string            `pulumi:"tdeWalletPassword"`
	// The date and time the pluggable database was created.
	TimeCreated string `pulumi:"timeCreated"`
}

func LookupPluggableDatabaseOutput(ctx *pulumi.Context, args LookupPluggableDatabaseOutputArgs, opts ...pulumi.InvokeOption) LookupPluggableDatabaseResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupPluggableDatabaseResultOutput, error) {
			args := v.(LookupPluggableDatabaseArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getPluggableDatabase:getPluggableDatabase", args, LookupPluggableDatabaseResultOutput{}, options).(LookupPluggableDatabaseResultOutput), nil
		}).(LookupPluggableDatabaseResultOutput)
}

// A collection of arguments for invoking getPluggableDatabase.
type LookupPluggableDatabaseOutputArgs struct {
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId pulumi.StringInput `pulumi:"pluggableDatabaseId"`
}

func (LookupPluggableDatabaseOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupPluggableDatabaseArgs)(nil)).Elem()
}

// A collection of values returned by getPluggableDatabase.
type LookupPluggableDatabaseResultOutput struct{ *pulumi.OutputState }

func (LookupPluggableDatabaseResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupPluggableDatabaseResult)(nil)).Elem()
}

func (o LookupPluggableDatabaseResultOutput) ToLookupPluggableDatabaseResultOutput() LookupPluggableDatabaseResultOutput {
	return o
}

func (o LookupPluggableDatabaseResultOutput) ToLookupPluggableDatabaseResultOutputWithContext(ctx context.Context) LookupPluggableDatabaseResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupPluggableDatabaseResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Connection strings to connect to an Oracle Pluggable Database.
func (o LookupPluggableDatabaseResultOutput) ConnectionStrings() GetPluggableDatabaseConnectionStringArrayOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) []GetPluggableDatabaseConnectionString {
		return v.ConnectionStrings
	}).(GetPluggableDatabaseConnectionStringArrayOutput)
}

func (o LookupPluggableDatabaseResultOutput) ContainerDatabaseAdminPassword() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.ContainerDatabaseAdminPassword }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
func (o LookupPluggableDatabaseResultOutput) ContainerDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.ContainerDatabaseId }).(pulumi.StringOutput)
}

func (o LookupPluggableDatabaseResultOutput) ConvertToRegularTrigger() pulumi.IntOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) int { return v.ConvertToRegularTrigger }).(pulumi.IntOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupPluggableDatabaseResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupPluggableDatabaseResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pluggable database.
func (o LookupPluggableDatabaseResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.Id }).(pulumi.StringOutput)
}

// The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
func (o LookupPluggableDatabaseResultOutput) IsRestricted() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) bool { return v.IsRestricted }).(pulumi.BoolOutput)
}

func (o LookupPluggableDatabaseResultOutput) KmsKeyVersionId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.KmsKeyVersionId }).(pulumi.StringOutput)
}

// Detailed message for the lifecycle state.
func (o LookupPluggableDatabaseResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
func (o LookupPluggableDatabaseResultOutput) OpenMode() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.OpenMode }).(pulumi.StringOutput)
}

func (o LookupPluggableDatabaseResultOutput) PdbAdminPassword() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.PdbAdminPassword }).(pulumi.StringOutput)
}

func (o LookupPluggableDatabaseResultOutput) PdbCreationTypeDetails() GetPluggableDatabasePdbCreationTypeDetailArrayOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) []GetPluggableDatabasePdbCreationTypeDetail {
		return v.PdbCreationTypeDetails
	}).(GetPluggableDatabasePdbCreationTypeDetailArrayOutput)
}

// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
func (o LookupPluggableDatabaseResultOutput) PdbName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.PdbName }).(pulumi.StringOutput)
}

// Pluggable Database Node Level Details. Example: [{"nodeName" : "node1", "openMode" : "READ_WRITE"}, {"nodeName" : "node2", "openMode" : "READ_ONLY"}]
func (o LookupPluggableDatabaseResultOutput) PdbNodeLevelDetails() GetPluggableDatabasePdbNodeLevelDetailArrayOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) []GetPluggableDatabasePdbNodeLevelDetail {
		return v.PdbNodeLevelDetails
	}).(GetPluggableDatabasePdbNodeLevelDetailArrayOutput)
}

func (o LookupPluggableDatabaseResultOutput) PluggableDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.PluggableDatabaseId }).(pulumi.StringOutput)
}

// The configuration of the Pluggable Database Management service.
func (o LookupPluggableDatabaseResultOutput) PluggableDatabaseManagementConfigs() GetPluggableDatabasePluggableDatabaseManagementConfigArrayOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) []GetPluggableDatabasePluggableDatabaseManagementConfig {
		return v.PluggableDatabaseManagementConfigs
	}).(GetPluggableDatabasePluggableDatabaseManagementConfigArrayOutput)
}

func (o LookupPluggableDatabaseResultOutput) RefreshTrigger() pulumi.IntOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) int { return v.RefreshTrigger }).(pulumi.IntOutput)
}

// Pluggable Database Refreshable Clone Configuration.
func (o LookupPluggableDatabaseResultOutput) RefreshableCloneConfigs() GetPluggableDatabaseRefreshableCloneConfigArrayOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) []GetPluggableDatabaseRefreshableCloneConfig {
		return v.RefreshableCloneConfigs
	}).(GetPluggableDatabaseRefreshableCloneConfigArrayOutput)
}

func (o LookupPluggableDatabaseResultOutput) RotateKeyTrigger() pulumi.IntOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) int { return v.RotateKeyTrigger }).(pulumi.IntOutput)
}

func (o LookupPluggableDatabaseResultOutput) ShouldCreatePdbBackup() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) bool { return v.ShouldCreatePdbBackup }).(pulumi.BoolOutput)
}

func (o LookupPluggableDatabaseResultOutput) ShouldPdbAdminAccountBeLocked() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) bool { return v.ShouldPdbAdminAccountBeLocked }).(pulumi.BoolOutput)
}

// The current state of the pluggable database.
func (o LookupPluggableDatabaseResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupPluggableDatabaseResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

func (o LookupPluggableDatabaseResultOutput) TdeWalletPassword() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.TdeWalletPassword }).(pulumi.StringOutput)
}

// The date and time the pluggable database was created.
func (o LookupPluggableDatabaseResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPluggableDatabaseResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupPluggableDatabaseResultOutput{})
}
