// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetTriggersTriggerCollectionItemActionFilterExclude;
import com.pulumi.oci.DevOps.outputs.GetTriggersTriggerCollectionItemActionFilterInclude;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetTriggersTriggerCollectionItemActionFilter {
    /**
     * @return The events, for example, PUSH, PULL_REQUEST_MERGE.
     * 
     */
    private List<String> events;
    private List<GetTriggersTriggerCollectionItemActionFilterExclude> excludes;
    /**
     * @return Attributes to filter GitLab self-hosted server events.
     * 
     */
    private List<GetTriggersTriggerCollectionItemActionFilterInclude> includes;
    /**
     * @return Source of the trigger. Allowed values are, GITHUB and GITLAB.
     * 
     */
    private String triggerSource;

    private GetTriggersTriggerCollectionItemActionFilter() {}
    /**
     * @return The events, for example, PUSH, PULL_REQUEST_MERGE.
     * 
     */
    public List<String> events() {
        return this.events;
    }
    public List<GetTriggersTriggerCollectionItemActionFilterExclude> excludes() {
        return this.excludes;
    }
    /**
     * @return Attributes to filter GitLab self-hosted server events.
     * 
     */
    public List<GetTriggersTriggerCollectionItemActionFilterInclude> includes() {
        return this.includes;
    }
    /**
     * @return Source of the trigger. Allowed values are, GITHUB and GITLAB.
     * 
     */
    public String triggerSource() {
        return this.triggerSource;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTriggersTriggerCollectionItemActionFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> events;
        private List<GetTriggersTriggerCollectionItemActionFilterExclude> excludes;
        private List<GetTriggersTriggerCollectionItemActionFilterInclude> includes;
        private String triggerSource;
        public Builder() {}
        public Builder(GetTriggersTriggerCollectionItemActionFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.events = defaults.events;
    	      this.excludes = defaults.excludes;
    	      this.includes = defaults.includes;
    	      this.triggerSource = defaults.triggerSource;
        }

        @CustomType.Setter
        public Builder events(List<String> events) {
            this.events = Objects.requireNonNull(events);
            return this;
        }
        public Builder events(String... events) {
            return events(List.of(events));
        }
        @CustomType.Setter
        public Builder excludes(List<GetTriggersTriggerCollectionItemActionFilterExclude> excludes) {
            this.excludes = Objects.requireNonNull(excludes);
            return this;
        }
        public Builder excludes(GetTriggersTriggerCollectionItemActionFilterExclude... excludes) {
            return excludes(List.of(excludes));
        }
        @CustomType.Setter
        public Builder includes(List<GetTriggersTriggerCollectionItemActionFilterInclude> includes) {
            this.includes = Objects.requireNonNull(includes);
            return this;
        }
        public Builder includes(GetTriggersTriggerCollectionItemActionFilterInclude... includes) {
            return includes(List.of(includes));
        }
        @CustomType.Setter
        public Builder triggerSource(String triggerSource) {
            this.triggerSource = Objects.requireNonNull(triggerSource);
            return this;
        }
        public GetTriggersTriggerCollectionItemActionFilter build() {
            final var o = new GetTriggersTriggerCollectionItemActionFilter();
            o.events = events;
            o.excludes = excludes;
            o.includes = includes;
            o.triggerSource = triggerSource;
            return o;
        }
    }
}