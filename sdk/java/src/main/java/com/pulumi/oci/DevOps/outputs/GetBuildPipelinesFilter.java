// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBuildPipelinesFilter {
    /**
     * @return Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
     * 
     */
    private String name;
    private @Nullable Boolean regex;
    private List<String> values;

    private GetBuildPipelinesFilter() {}
    /**
     * @return Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
     * 
     */
    public String name() {
        return this.name;
    }
    public Optional<Boolean> regex() {
        return Optional.ofNullable(this.regex);
    }
    public List<String> values() {
        return this.values;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildPipelinesFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private @Nullable Boolean regex;
        private List<String> values;
        public Builder() {}
        public Builder(GetBuildPipelinesFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.regex = defaults.regex;
    	      this.values = defaults.values;
        }

        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder regex(@Nullable Boolean regex) {
            this.regex = regex;
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
        public GetBuildPipelinesFilter build() {
            final var o = new GetBuildPipelinesFilter();
            o.name = name;
            o.regex = regex;
            o.values = values;
            return o;
        }
    }
}