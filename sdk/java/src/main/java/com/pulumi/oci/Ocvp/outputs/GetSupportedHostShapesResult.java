// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Ocvp.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Ocvp.outputs.GetSupportedHostShapesFilter;
import com.pulumi.oci.Ocvp.outputs.GetSupportedHostShapesItem;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSupportedHostShapesResult {
    private String compartmentId;
    private @Nullable List<GetSupportedHostShapesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String initialHostShapeName;
    /**
     * @return Indicates whether the shape supports single host SDDCs.
     * 
     */
    private @Nullable Boolean isSingleHostSddcSupported;
    /**
     * @return A list of the supported compute shapes for ESXi hosts.
     * 
     */
    private List<GetSupportedHostShapesItem> items;
    /**
     * @return The name of the supported compute shape.
     * 
     */
    private @Nullable String name;
    /**
     * @deprecated
     * The &#39;sddc_type&#39; field has been deprecated. Please use &#39;is_single_host_sddc_supported&#39; instead.
     * 
     */
    @Deprecated /* The 'sddc_type' field has been deprecated. Please use 'is_single_host_sddc_supported' instead. */
    private @Nullable String sddcType;

    private GetSupportedHostShapesResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetSupportedHostShapesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> initialHostShapeName() {
        return Optional.ofNullable(this.initialHostShapeName);
    }
    /**
     * @return Indicates whether the shape supports single host SDDCs.
     * 
     */
    public Optional<Boolean> isSingleHostSddcSupported() {
        return Optional.ofNullable(this.isSingleHostSddcSupported);
    }
    /**
     * @return A list of the supported compute shapes for ESXi hosts.
     * 
     */
    public List<GetSupportedHostShapesItem> items() {
        return this.items;
    }
    /**
     * @return The name of the supported compute shape.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @deprecated
     * The &#39;sddc_type&#39; field has been deprecated. Please use &#39;is_single_host_sddc_supported&#39; instead.
     * 
     */
    @Deprecated /* The 'sddc_type' field has been deprecated. Please use 'is_single_host_sddc_supported' instead. */
    public Optional<String> sddcType() {
        return Optional.ofNullable(this.sddcType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSupportedHostShapesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetSupportedHostShapesFilter> filters;
        private String id;
        private @Nullable String initialHostShapeName;
        private @Nullable Boolean isSingleHostSddcSupported;
        private List<GetSupportedHostShapesItem> items;
        private @Nullable String name;
        private @Nullable String sddcType;
        public Builder() {}
        public Builder(GetSupportedHostShapesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.initialHostShapeName = defaults.initialHostShapeName;
    	      this.isSingleHostSddcSupported = defaults.isSingleHostSddcSupported;
    	      this.items = defaults.items;
    	      this.name = defaults.name;
    	      this.sddcType = defaults.sddcType;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSupportedHostShapesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSupportedHostShapesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetSupportedHostShapesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSupportedHostShapesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder initialHostShapeName(@Nullable String initialHostShapeName) {

            this.initialHostShapeName = initialHostShapeName;
            return this;
        }
        @CustomType.Setter
        public Builder isSingleHostSddcSupported(@Nullable Boolean isSingleHostSddcSupported) {

            this.isSingleHostSddcSupported = isSingleHostSddcSupported;
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetSupportedHostShapesItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetSupportedHostShapesResult", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetSupportedHostShapesItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder sddcType(@Nullable String sddcType) {

            this.sddcType = sddcType;
            return this;
        }
        public GetSupportedHostShapesResult build() {
            final var _resultValue = new GetSupportedHostShapesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.initialHostShapeName = initialHostShapeName;
            _resultValue.isSingleHostSddcSupported = isSingleHostSddcSupported;
            _resultValue.items = items;
            _resultValue.name = name;
            _resultValue.sddcType = sddcType;
            return _resultValue;
        }
    }
}
