// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.TriggerActionFilterExclude;
import com.pulumi.oci.DevOps.outputs.TriggerActionFilterInclude;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class TriggerActionFilter {
    /**
     * @return (Updatable) The events, for example, PUSH, PULL_REQUEST_MERGE.
     * 
     */
    private @Nullable List<String> events;
    private @Nullable TriggerActionFilterExclude exclude;
    /**
     * @return (Updatable) Attributes to filter GitLab self-hosted server events.
     * 
     */
    private @Nullable TriggerActionFilterInclude include;
    /**
     * @return (Updatable) Source of the trigger. Allowed values are, GITHUB,GITLAB and BITBUCKET_CLOUD.
     * 
     */
    private String triggerSource;

    private TriggerActionFilter() {}
    /**
     * @return (Updatable) The events, for example, PUSH, PULL_REQUEST_MERGE.
     * 
     */
    public List<String> events() {
        return this.events == null ? List.of() : this.events;
    }
    public Optional<TriggerActionFilterExclude> exclude() {
        return Optional.ofNullable(this.exclude);
    }
    /**
     * @return (Updatable) Attributes to filter GitLab self-hosted server events.
     * 
     */
    public Optional<TriggerActionFilterInclude> include() {
        return Optional.ofNullable(this.include);
    }
    /**
     * @return (Updatable) Source of the trigger. Allowed values are, GITHUB,GITLAB and BITBUCKET_CLOUD.
     * 
     */
    public String triggerSource() {
        return this.triggerSource;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TriggerActionFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> events;
        private @Nullable TriggerActionFilterExclude exclude;
        private @Nullable TriggerActionFilterInclude include;
        private String triggerSource;
        public Builder() {}
        public Builder(TriggerActionFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.events = defaults.events;
    	      this.exclude = defaults.exclude;
    	      this.include = defaults.include;
    	      this.triggerSource = defaults.triggerSource;
        }

        @CustomType.Setter
        public Builder events(@Nullable List<String> events) {
            this.events = events;
            return this;
        }
        public Builder events(String... events) {
            return events(List.of(events));
        }
        @CustomType.Setter
        public Builder exclude(@Nullable TriggerActionFilterExclude exclude) {
            this.exclude = exclude;
            return this;
        }
        @CustomType.Setter
        public Builder include(@Nullable TriggerActionFilterInclude include) {
            this.include = include;
            return this;
        }
        @CustomType.Setter
        public Builder triggerSource(String triggerSource) {
            this.triggerSource = Objects.requireNonNull(triggerSource);
            return this;
        }
        public TriggerActionFilter build() {
            final var o = new TriggerActionFilter();
            o.events = events;
            o.exclude = exclude;
            o.include = include;
            o.triggerSource = triggerSource;
            return o;
        }
    }
}