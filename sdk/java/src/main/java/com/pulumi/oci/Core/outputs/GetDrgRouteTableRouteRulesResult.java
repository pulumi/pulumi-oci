// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetDrgRouteTableRouteRulesDrgRouteRule;
import com.pulumi.oci.Core.outputs.GetDrgRouteTableRouteRulesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDrgRouteTableRouteRulesResult {
    /**
     * @return The list of drg_route_rules.
     * 
     */
    private List<GetDrgRouteTableRouteRulesDrgRouteRule> drgRouteRules;
    private String drgRouteTableId;
    private @Nullable List<GetDrgRouteTableRouteRulesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return You can specify static routes for the DRG route table using the API. The DRG learns dynamic routes from the DRG attachments using various routing protocols.
     * 
     */
    private @Nullable String routeType;

    private GetDrgRouteTableRouteRulesResult() {}
    /**
     * @return The list of drg_route_rules.
     * 
     */
    public List<GetDrgRouteTableRouteRulesDrgRouteRule> drgRouteRules() {
        return this.drgRouteRules;
    }
    public String drgRouteTableId() {
        return this.drgRouteTableId;
    }
    public List<GetDrgRouteTableRouteRulesFilter> filters() {
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
     * @return You can specify static routes for the DRG route table using the API. The DRG learns dynamic routes from the DRG attachments using various routing protocols.
     * 
     */
    public Optional<String> routeType() {
        return Optional.ofNullable(this.routeType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDrgRouteTableRouteRulesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDrgRouteTableRouteRulesDrgRouteRule> drgRouteRules;
        private String drgRouteTableId;
        private @Nullable List<GetDrgRouteTableRouteRulesFilter> filters;
        private String id;
        private @Nullable String routeType;
        public Builder() {}
        public Builder(GetDrgRouteTableRouteRulesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.drgRouteRules = defaults.drgRouteRules;
    	      this.drgRouteTableId = defaults.drgRouteTableId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.routeType = defaults.routeType;
        }

        @CustomType.Setter
        public Builder drgRouteRules(List<GetDrgRouteTableRouteRulesDrgRouteRule> drgRouteRules) {
            this.drgRouteRules = Objects.requireNonNull(drgRouteRules);
            return this;
        }
        public Builder drgRouteRules(GetDrgRouteTableRouteRulesDrgRouteRule... drgRouteRules) {
            return drgRouteRules(List.of(drgRouteRules));
        }
        @CustomType.Setter
        public Builder drgRouteTableId(String drgRouteTableId) {
            this.drgRouteTableId = Objects.requireNonNull(drgRouteTableId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDrgRouteTableRouteRulesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDrgRouteTableRouteRulesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder routeType(@Nullable String routeType) {
            this.routeType = routeType;
            return this;
        }
        public GetDrgRouteTableRouteRulesResult build() {
            final var o = new GetDrgRouteTableRouteRulesResult();
            o.drgRouteRules = drgRouteRules;
            o.drgRouteTableId = drgRouteTableId;
            o.filters = filters;
            o.id = id;
            o.routeType = routeType;
            return o;
        }
    }
}