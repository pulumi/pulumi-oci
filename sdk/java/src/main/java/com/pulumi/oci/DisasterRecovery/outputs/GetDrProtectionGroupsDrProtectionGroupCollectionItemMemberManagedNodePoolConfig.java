// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberManagedNodePoolConfig {
    /**
     * @return The OCID of the virtual node pool in OKE cluster.
     * 
     */
    private String id;
    /**
     * @return The maximum number to which nodes in the virtual node pool could be scaled up.
     * 
     */
    private Integer maximum;
    /**
     * @return The minimum number to which nodes in the virtual node pool could be scaled down.
     * 
     */
    private Integer minimum;

    private GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberManagedNodePoolConfig() {}
    /**
     * @return The OCID of the virtual node pool in OKE cluster.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The maximum number to which nodes in the virtual node pool could be scaled up.
     * 
     */
    public Integer maximum() {
        return this.maximum;
    }
    /**
     * @return The minimum number to which nodes in the virtual node pool could be scaled down.
     * 
     */
    public Integer minimum() {
        return this.minimum;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberManagedNodePoolConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private Integer maximum;
        private Integer minimum;
        public Builder() {}
        public Builder(GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberManagedNodePoolConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.maximum = defaults.maximum;
    	      this.minimum = defaults.minimum;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberManagedNodePoolConfig", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder maximum(Integer maximum) {
            if (maximum == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberManagedNodePoolConfig", "maximum");
            }
            this.maximum = maximum;
            return this;
        }
        @CustomType.Setter
        public Builder minimum(Integer minimum) {
            if (minimum == null) {
              throw new MissingRequiredPropertyException("GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberManagedNodePoolConfig", "minimum");
            }
            this.minimum = minimum;
            return this;
        }
        public GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberManagedNodePoolConfig build() {
            final var _resultValue = new GetDrProtectionGroupsDrProtectionGroupCollectionItemMemberManagedNodePoolConfig();
            _resultValue.id = id;
            _resultValue.maximum = maximum;
            _resultValue.minimum = minimum;
            return _resultValue;
        }
    }
}
