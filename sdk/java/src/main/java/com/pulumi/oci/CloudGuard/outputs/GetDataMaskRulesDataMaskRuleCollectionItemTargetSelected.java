// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected {
    /**
     * @return Target selection.
     * 
     */
    private String kind;
    /**
     * @return Types of Targets
     * 
     */
    private List<String> values;

    private GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected() {}
    /**
     * @return Target selection.
     * 
     */
    public String kind() {
        return this.kind;
    }
    /**
     * @return Types of Targets
     * 
     */
    public List<String> values() {
        return this.values;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String kind;
        private List<String> values;
        public Builder() {}
        public Builder(GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.kind = defaults.kind;
    	      this.values = defaults.values;
        }

        @CustomType.Setter
        public Builder kind(String kind) {
            this.kind = Objects.requireNonNull(kind);
            return this;
        }
        @CustomType.Setter
        public Builder values(List<String> values) {
            this.values = Objects.requireNonNull(values);
            return this;
        }
        public Builder values(String... values) {
            return values(List.of(values));
        }
        public GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected build() {
            final var o = new GetDataMaskRulesDataMaskRuleCollectionItemTargetSelected();
            o.kind = kind;
            o.values = values;
            return o;
        }
    }
}