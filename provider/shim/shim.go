package shim

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/terraform-providers/terraform-provider-oci/internal/provider"
)

func NewProvider() *schema.Provider {
	return provider.Provider()
}
