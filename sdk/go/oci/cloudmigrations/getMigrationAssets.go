// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudmigrations

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Migration Assets in Oracle Cloud Infrastructure Cloud Migrations service.
//
// Returns a list of migration assets.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudmigrations"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudmigrations.GetMigrationAssets(ctx, &cloudmigrations.GetMigrationAssetsArgs{
//				DisplayName:      pulumi.StringRef(migrationAssetDisplayName),
//				MigrationAssetId: pulumi.StringRef(testMigrationAsset.Id),
//				MigrationId:      pulumi.StringRef(testMigration.Id),
//				State:            pulumi.StringRef(migrationAssetState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMigrationAssets(ctx *pulumi.Context, args *GetMigrationAssetsArgs, opts ...pulumi.InvokeOption) (*GetMigrationAssetsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetMigrationAssetsResult
	err := ctx.Invoke("oci:CloudMigrations/getMigrationAssets:getMigrationAssets", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMigrationAssets.
type GetMigrationAssetsArgs struct {
	// A filter to return only resources that match the entire given display name.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetMigrationAssetsFilter `pulumi:"filters"`
	// Unique migration asset identifier
	MigrationAssetId *string `pulumi:"migrationAssetId"`
	// Unique migration identifier
	MigrationId *string `pulumi:"migrationId"`
	// The current state of the migration asset.
	State *string `pulumi:"state"`
}

// A collection of values returned by getMigrationAssets.
type GetMigrationAssetsResult struct {
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                    `pulumi:"displayName"`
	Filters     []GetMigrationAssetsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of migration_asset_collection.
	MigrationAssetCollections []GetMigrationAssetsMigrationAssetCollection `pulumi:"migrationAssetCollections"`
	MigrationAssetId          *string                                      `pulumi:"migrationAssetId"`
	// OCID of the associated migration.
	MigrationId *string `pulumi:"migrationId"`
	// The current state of the migration asset.
	State *string `pulumi:"state"`
}

func GetMigrationAssetsOutput(ctx *pulumi.Context, args GetMigrationAssetsOutputArgs, opts ...pulumi.InvokeOption) GetMigrationAssetsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetMigrationAssetsResultOutput, error) {
			args := v.(GetMigrationAssetsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CloudMigrations/getMigrationAssets:getMigrationAssets", args, GetMigrationAssetsResultOutput{}, options).(GetMigrationAssetsResultOutput), nil
		}).(GetMigrationAssetsResultOutput)
}

// A collection of arguments for invoking getMigrationAssets.
type GetMigrationAssetsOutputArgs struct {
	// A filter to return only resources that match the entire given display name.
	DisplayName pulumi.StringPtrInput              `pulumi:"displayName"`
	Filters     GetMigrationAssetsFilterArrayInput `pulumi:"filters"`
	// Unique migration asset identifier
	MigrationAssetId pulumi.StringPtrInput `pulumi:"migrationAssetId"`
	// Unique migration identifier
	MigrationId pulumi.StringPtrInput `pulumi:"migrationId"`
	// The current state of the migration asset.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetMigrationAssetsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMigrationAssetsArgs)(nil)).Elem()
}

// A collection of values returned by getMigrationAssets.
type GetMigrationAssetsResultOutput struct{ *pulumi.OutputState }

func (GetMigrationAssetsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMigrationAssetsResult)(nil)).Elem()
}

func (o GetMigrationAssetsResultOutput) ToGetMigrationAssetsResultOutput() GetMigrationAssetsResultOutput {
	return o
}

func (o GetMigrationAssetsResultOutput) ToGetMigrationAssetsResultOutputWithContext(ctx context.Context) GetMigrationAssetsResultOutput {
	return o
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetMigrationAssetsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationAssetsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetMigrationAssetsResultOutput) Filters() GetMigrationAssetsFilterArrayOutput {
	return o.ApplyT(func(v GetMigrationAssetsResult) []GetMigrationAssetsFilter { return v.Filters }).(GetMigrationAssetsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMigrationAssetsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMigrationAssetsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of migration_asset_collection.
func (o GetMigrationAssetsResultOutput) MigrationAssetCollections() GetMigrationAssetsMigrationAssetCollectionArrayOutput {
	return o.ApplyT(func(v GetMigrationAssetsResult) []GetMigrationAssetsMigrationAssetCollection {
		return v.MigrationAssetCollections
	}).(GetMigrationAssetsMigrationAssetCollectionArrayOutput)
}

func (o GetMigrationAssetsResultOutput) MigrationAssetId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationAssetsResult) *string { return v.MigrationAssetId }).(pulumi.StringPtrOutput)
}

// OCID of the associated migration.
func (o GetMigrationAssetsResultOutput) MigrationId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationAssetsResult) *string { return v.MigrationId }).(pulumi.StringPtrOutput)
}

// The current state of the migration asset.
func (o GetMigrationAssetsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationAssetsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMigrationAssetsResultOutput{})
}
