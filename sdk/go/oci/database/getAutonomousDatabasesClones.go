// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Autonomous Databases Clones in Oracle Cloud Infrastructure Database service.
//
// Lists the Autonomous Database clones for the specified Autonomous Database.
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
//			_, err := database.GetAutonomousDatabasesClones(ctx, &database.GetAutonomousDatabasesClonesArgs{
//				AutonomousDatabaseId: testAutonomousDatabase.Id,
//				CompartmentId:        compartmentId,
//				CloneType:            pulumi.StringRef(autonomousDatabasesCloneCloneType),
//				DisplayName:          pulumi.StringRef(autonomousDatabasesCloneDisplayName),
//				State:                pulumi.StringRef(autonomousDatabasesCloneState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAutonomousDatabasesClones(ctx *pulumi.Context, args *GetAutonomousDatabasesClonesArgs, opts ...pulumi.InvokeOption) (*GetAutonomousDatabasesClonesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetAutonomousDatabasesClonesResult
	err := ctx.Invoke("oci:Database/getAutonomousDatabasesClones:getAutonomousDatabasesClones", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousDatabasesClones.
type GetAutonomousDatabasesClonesArgs struct {
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseId string `pulumi:"autonomousDatabaseId"`
	// A filter to return only resources that match the given clone type exactly.
	CloneType *string `pulumi:"cloneType"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string                              `pulumi:"displayName"`
	Filters     []GetAutonomousDatabasesClonesFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAutonomousDatabasesClones.
type GetAutonomousDatabasesClonesResult struct {
	AutonomousDatabaseId string `pulumi:"autonomousDatabaseId"`
	// The list of autonomous_databases.
	AutonomousDatabases []GetAutonomousDatabasesClonesAutonomousDatabase `pulumi:"autonomousDatabases"`
	CloneType           *string                                          `pulumi:"cloneType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly name for the Autonomous Database. The name does not have to be unique.
	DisplayName *string                              `pulumi:"displayName"`
	Filters     []GetAutonomousDatabasesClonesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the Autonomous Database.
	State *string `pulumi:"state"`
}

func GetAutonomousDatabasesClonesOutput(ctx *pulumi.Context, args GetAutonomousDatabasesClonesOutputArgs, opts ...pulumi.InvokeOption) GetAutonomousDatabasesClonesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetAutonomousDatabasesClonesResultOutput, error) {
			args := v.(GetAutonomousDatabasesClonesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getAutonomousDatabasesClones:getAutonomousDatabasesClones", args, GetAutonomousDatabasesClonesResultOutput{}, options).(GetAutonomousDatabasesClonesResultOutput), nil
		}).(GetAutonomousDatabasesClonesResultOutput)
}

// A collection of arguments for invoking getAutonomousDatabasesClones.
type GetAutonomousDatabasesClonesOutputArgs struct {
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousDatabaseId pulumi.StringInput `pulumi:"autonomousDatabaseId"`
	// A filter to return only resources that match the given clone type exactly.
	CloneType pulumi.StringPtrInput `pulumi:"cloneType"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName pulumi.StringPtrInput                        `pulumi:"displayName"`
	Filters     GetAutonomousDatabasesClonesFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetAutonomousDatabasesClonesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutonomousDatabasesClonesArgs)(nil)).Elem()
}

// A collection of values returned by getAutonomousDatabasesClones.
type GetAutonomousDatabasesClonesResultOutput struct{ *pulumi.OutputState }

func (GetAutonomousDatabasesClonesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutonomousDatabasesClonesResult)(nil)).Elem()
}

func (o GetAutonomousDatabasesClonesResultOutput) ToGetAutonomousDatabasesClonesResultOutput() GetAutonomousDatabasesClonesResultOutput {
	return o
}

func (o GetAutonomousDatabasesClonesResultOutput) ToGetAutonomousDatabasesClonesResultOutputWithContext(ctx context.Context) GetAutonomousDatabasesClonesResultOutput {
	return o
}

func (o GetAutonomousDatabasesClonesResultOutput) AutonomousDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabasesClonesResult) string { return v.AutonomousDatabaseId }).(pulumi.StringOutput)
}

// The list of autonomous_databases.
func (o GetAutonomousDatabasesClonesResultOutput) AutonomousDatabases() GetAutonomousDatabasesClonesAutonomousDatabaseArrayOutput {
	return o.ApplyT(func(v GetAutonomousDatabasesClonesResult) []GetAutonomousDatabasesClonesAutonomousDatabase {
		return v.AutonomousDatabases
	}).(GetAutonomousDatabasesClonesAutonomousDatabaseArrayOutput)
}

func (o GetAutonomousDatabasesClonesResultOutput) CloneType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutonomousDatabasesClonesResult) *string { return v.CloneType }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetAutonomousDatabasesClonesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabasesClonesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The user-friendly name for the Autonomous Database. The name does not have to be unique.
func (o GetAutonomousDatabasesClonesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutonomousDatabasesClonesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetAutonomousDatabasesClonesResultOutput) Filters() GetAutonomousDatabasesClonesFilterArrayOutput {
	return o.ApplyT(func(v GetAutonomousDatabasesClonesResult) []GetAutonomousDatabasesClonesFilter { return v.Filters }).(GetAutonomousDatabasesClonesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAutonomousDatabasesClonesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousDatabasesClonesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the Autonomous Database.
func (o GetAutonomousDatabasesClonesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutonomousDatabasesClonesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAutonomousDatabasesClonesResultOutput{})
}
