// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetCustomerSecretKeysCustomerSecretKey;
import com.pulumi.oci.Identity.outputs.GetCustomerSecretKeysFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetCustomerSecretKeysResult {
    /**
     * @return The list of customer_secret_keys.
     * 
     */
    private List<GetCustomerSecretKeysCustomerSecretKey> customerSecretKeys;
    private @Nullable List<GetCustomerSecretKeysFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID of the user the password belongs to.
     * 
     */
    private String userId;

    private GetCustomerSecretKeysResult() {}
    /**
     * @return The list of customer_secret_keys.
     * 
     */
    public List<GetCustomerSecretKeysCustomerSecretKey> customerSecretKeys() {
        return this.customerSecretKeys;
    }
    public List<GetCustomerSecretKeysFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The OCID of the user the password belongs to.
     * 
     */
    public String userId() {
        return this.userId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCustomerSecretKeysResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetCustomerSecretKeysCustomerSecretKey> customerSecretKeys;
        private @Nullable List<GetCustomerSecretKeysFilter> filters;
        private String id;
        private String userId;
        public Builder() {}
        public Builder(GetCustomerSecretKeysResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.customerSecretKeys = defaults.customerSecretKeys;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.userId = defaults.userId;
        }

        @CustomType.Setter
        public Builder customerSecretKeys(List<GetCustomerSecretKeysCustomerSecretKey> customerSecretKeys) {
            this.customerSecretKeys = Objects.requireNonNull(customerSecretKeys);
            return this;
        }
        public Builder customerSecretKeys(GetCustomerSecretKeysCustomerSecretKey... customerSecretKeys) {
            return customerSecretKeys(List.of(customerSecretKeys));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetCustomerSecretKeysFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetCustomerSecretKeysFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder userId(String userId) {
            this.userId = Objects.requireNonNull(userId);
            return this;
        }
        public GetCustomerSecretKeysResult build() {
            final var o = new GetCustomerSecretKeysResult();
            o.customerSecretKeys = customerSecretKeys;
            o.filters = filters;
            o.id = id;
            o.userId = userId;
            return o;
        }
    }
}