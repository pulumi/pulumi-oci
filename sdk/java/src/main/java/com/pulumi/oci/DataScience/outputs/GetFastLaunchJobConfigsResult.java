// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataScience.outputs.GetFastLaunchJobConfigsFastLaunchJobConfig;
import com.pulumi.oci.DataScience.outputs.GetFastLaunchJobConfigsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetFastLaunchJobConfigsResult {
    private String compartmentId;
    /**
     * @return The list of fast_launch_job_configs.
     * 
     */
    private List<GetFastLaunchJobConfigsFastLaunchJobConfig> fastLaunchJobConfigs;
    private @Nullable List<GetFastLaunchJobConfigsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetFastLaunchJobConfigsResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of fast_launch_job_configs.
     * 
     */
    public List<GetFastLaunchJobConfigsFastLaunchJobConfig> fastLaunchJobConfigs() {
        return this.fastLaunchJobConfigs;
    }
    public List<GetFastLaunchJobConfigsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFastLaunchJobConfigsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetFastLaunchJobConfigsFastLaunchJobConfig> fastLaunchJobConfigs;
        private @Nullable List<GetFastLaunchJobConfigsFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetFastLaunchJobConfigsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.fastLaunchJobConfigs = defaults.fastLaunchJobConfigs;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder fastLaunchJobConfigs(List<GetFastLaunchJobConfigsFastLaunchJobConfig> fastLaunchJobConfigs) {
            this.fastLaunchJobConfigs = Objects.requireNonNull(fastLaunchJobConfigs);
            return this;
        }
        public Builder fastLaunchJobConfigs(GetFastLaunchJobConfigsFastLaunchJobConfig... fastLaunchJobConfigs) {
            return fastLaunchJobConfigs(List.of(fastLaunchJobConfigs));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetFastLaunchJobConfigsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetFastLaunchJobConfigsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetFastLaunchJobConfigsResult build() {
            final var o = new GetFastLaunchJobConfigsResult();
            o.compartmentId = compartmentId;
            o.fastLaunchJobConfigs = fastLaunchJobConfigs;
            o.filters = filters;
            o.id = id;
            return o;
        }
    }
}