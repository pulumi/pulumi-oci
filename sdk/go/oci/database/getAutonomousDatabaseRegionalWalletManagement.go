// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Autonomous Database Regional Wallet Management resource in Oracle Cloud Infrastructure Database service.
//
// Gets the Autonomous Database regional wallet details.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Database.GetAutonomousDatabaseRegionalWalletManagement(ctx, nil, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupAutonomousDatabaseRegionalWalletManagement(ctx *pulumi.Context, opts ...pulumi.InvokeOption) (*LookupAutonomousDatabaseRegionalWalletManagementResult, error) {
	var rv LookupAutonomousDatabaseRegionalWalletManagementResult
	err := ctx.Invoke("oci:Database/getAutonomousDatabaseRegionalWalletManagement:getAutonomousDatabaseRegionalWalletManagement", nil, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of values returned by getAutonomousDatabaseRegionalWalletManagement.
type LookupAutonomousDatabaseRegionalWalletManagementResult struct {
	GracePeriod  int    `pulumi:"gracePeriod"`
	Id           string `pulumi:"id"`
	ShouldRotate bool   `pulumi:"shouldRotate"`
	// The current lifecycle state of the Autonomous Database wallet.
	State string `pulumi:"state"`
	// The date and time the wallet was last rotated.
	TimeRotated string `pulumi:"timeRotated"`
}