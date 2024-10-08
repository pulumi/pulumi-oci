// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DefaultRouteTableRouteRule {
    /**
     * @deprecated
     * The &#39;cidr_block&#39; field has been deprecated. Please use &#39;destination&#39; instead.
     * 
     */
    @Deprecated /* The 'cidr_block' field has been deprecated. Please use 'destination' instead. */
    private @Nullable String cidrBlock;
    private @Nullable String description;
    private @Nullable String destination;
    private @Nullable String destinationType;
    private String networkEntityId;
    private @Nullable String routeType;

    private DefaultRouteTableRouteRule() {}
    /**
     * @deprecated
     * The &#39;cidr_block&#39; field has been deprecated. Please use &#39;destination&#39; instead.
     * 
     */
    @Deprecated /* The 'cidr_block' field has been deprecated. Please use 'destination' instead. */
    public Optional<String> cidrBlock() {
        return Optional.ofNullable(this.cidrBlock);
    }
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    public Optional<String> destination() {
        return Optional.ofNullable(this.destination);
    }
    public Optional<String> destinationType() {
        return Optional.ofNullable(this.destinationType);
    }
    public String networkEntityId() {
        return this.networkEntityId;
    }
    public Optional<String> routeType() {
        return Optional.ofNullable(this.routeType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DefaultRouteTableRouteRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String cidrBlock;
        private @Nullable String description;
        private @Nullable String destination;
        private @Nullable String destinationType;
        private String networkEntityId;
        private @Nullable String routeType;
        public Builder() {}
        public Builder(DefaultRouteTableRouteRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cidrBlock = defaults.cidrBlock;
    	      this.description = defaults.description;
    	      this.destination = defaults.destination;
    	      this.destinationType = defaults.destinationType;
    	      this.networkEntityId = defaults.networkEntityId;
    	      this.routeType = defaults.routeType;
        }

        @CustomType.Setter
        public Builder cidrBlock(@Nullable String cidrBlock) {

            this.cidrBlock = cidrBlock;
            return this;
        }
        @CustomType.Setter
        public Builder description(@Nullable String description) {

            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder destination(@Nullable String destination) {

            this.destination = destination;
            return this;
        }
        @CustomType.Setter
        public Builder destinationType(@Nullable String destinationType) {

            this.destinationType = destinationType;
            return this;
        }
        @CustomType.Setter
        public Builder networkEntityId(String networkEntityId) {
            if (networkEntityId == null) {
              throw new MissingRequiredPropertyException("DefaultRouteTableRouteRule", "networkEntityId");
            }
            this.networkEntityId = networkEntityId;
            return this;
        }
        @CustomType.Setter
        public Builder routeType(@Nullable String routeType) {

            this.routeType = routeType;
            return this;
        }
        public DefaultRouteTableRouteRule build() {
            final var _resultValue = new DefaultRouteTableRouteRule();
            _resultValue.cidrBlock = cidrBlock;
            _resultValue.description = description;
            _resultValue.destination = destination;
            _resultValue.destinationType = destinationType;
            _resultValue.networkEntityId = networkEntityId;
            _resultValue.routeType = routeType;
            return _resultValue;
        }
    }
}
