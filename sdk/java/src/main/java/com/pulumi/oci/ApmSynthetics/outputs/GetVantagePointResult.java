// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApmSynthetics.outputs.GetVantagePointItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetVantagePointResult {
    private String apmDomainId;
    /**
     * @return Unique name that can be edited. The name should not contain any confidential information.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return List of PublicVantagePointSummary items.
     * 
     */
    private List<GetVantagePointItem> items;
    /**
     * @return Unique permanent name of the vantage point.
     * 
     */
    private @Nullable String name;

    private GetVantagePointResult() {}
    public String apmDomainId() {
        return this.apmDomainId;
    }
    /**
     * @return Unique name that can be edited. The name should not contain any confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return List of PublicVantagePointSummary items.
     * 
     */
    public List<GetVantagePointItem> items() {
        return this.items;
    }
    /**
     * @return Unique permanent name of the vantage point.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVantagePointResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apmDomainId;
        private @Nullable String displayName;
        private String id;
        private List<GetVantagePointItem> items;
        private @Nullable String name;
        public Builder() {}
        public Builder(GetVantagePointResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apmDomainId = defaults.apmDomainId;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder apmDomainId(String apmDomainId) {
            this.apmDomainId = Objects.requireNonNull(apmDomainId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetVantagePointItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetVantagePointItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        public GetVantagePointResult build() {
            final var o = new GetVantagePointResult();
            o.apmDomainId = apmDomainId;
            o.displayName = displayName;
            o.id = id;
            o.items = items;
            o.name = name;
            return o;
        }
    }
}