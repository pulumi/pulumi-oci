// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDrProtectionGroupMemberBackendSetMapping {
    /**
     * @return The name of the destination backend set.  Example: `My_Destination_Backend_Set`
     * 
     */
    private String destinationBackendSetName;
    /**
     * @return This flag specifies if this backend set is used for traffic for non-movable compute instances. Backend sets that point to non-movable instances are only enabled or disabled during DR. For non-movable instances this flag should be set to &#39;true&#39;. Backend sets that point to movable instances are emptied and their contents are transferred to the destination region network load balancer.  For movable instances this flag should be set to &#39;false&#39;.   Example: `true`
     * 
     */
    private Boolean isBackendSetForNonMovable;
    /**
     * @return The name of the source backend set.  Example: `My_Source_Backend_Set`
     * 
     */
    private String sourceBackendSetName;

    private GetDrProtectionGroupMemberBackendSetMapping() {}
    /**
     * @return The name of the destination backend set.  Example: `My_Destination_Backend_Set`
     * 
     */
    public String destinationBackendSetName() {
        return this.destinationBackendSetName;
    }
    /**
     * @return This flag specifies if this backend set is used for traffic for non-movable compute instances. Backend sets that point to non-movable instances are only enabled or disabled during DR. For non-movable instances this flag should be set to &#39;true&#39;. Backend sets that point to movable instances are emptied and their contents are transferred to the destination region network load balancer.  For movable instances this flag should be set to &#39;false&#39;.   Example: `true`
     * 
     */
    public Boolean isBackendSetForNonMovable() {
        return this.isBackendSetForNonMovable;
    }
    /**
     * @return The name of the source backend set.  Example: `My_Source_Backend_Set`
     * 
     */
    public String sourceBackendSetName() {
        return this.sourceBackendSetName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrProtectionGroupMemberBackendSetMapping defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String destinationBackendSetName;
        private Boolean isBackendSetForNonMovable;
        private String sourceBackendSetName;
        public Builder() {}
        public Builder(GetDrProtectionGroupMemberBackendSetMapping defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.destinationBackendSetName = defaults.destinationBackendSetName;
    	      this.isBackendSetForNonMovable = defaults.isBackendSetForNonMovable;
    	      this.sourceBackendSetName = defaults.sourceBackendSetName;
        }

        @CustomType.Setter
        public Builder destinationBackendSetName(String destinationBackendSetName) {
            this.destinationBackendSetName = Objects.requireNonNull(destinationBackendSetName);
            return this;
        }
        @CustomType.Setter
        public Builder isBackendSetForNonMovable(Boolean isBackendSetForNonMovable) {
            this.isBackendSetForNonMovable = Objects.requireNonNull(isBackendSetForNonMovable);
            return this;
        }
        @CustomType.Setter
        public Builder sourceBackendSetName(String sourceBackendSetName) {
            this.sourceBackendSetName = Objects.requireNonNull(sourceBackendSetName);
            return this;
        }
        public GetDrProtectionGroupMemberBackendSetMapping build() {
            final var o = new GetDrProtectionGroupMemberBackendSetMapping();
            o.destinationBackendSetName = destinationBackendSetName;
            o.isBackendSetForNonMovable = isBackendSetForNonMovable;
            o.sourceBackendSetName = sourceBackendSetName;
            return o;
        }
    }
}