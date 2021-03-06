// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetProjectNotificationConfig {
    /**
     * @return The topic ID for notifications.
     * 
     */
    private final String topicId;

    @CustomType.Constructor
    private GetProjectNotificationConfig(@CustomType.Parameter("topicId") String topicId) {
        this.topicId = topicId;
    }

    /**
     * @return The topic ID for notifications.
     * 
     */
    public String topicId() {
        return this.topicId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProjectNotificationConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String topicId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetProjectNotificationConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.topicId = defaults.topicId;
        }

        public Builder topicId(String topicId) {
            this.topicId = Objects.requireNonNull(topicId);
            return this;
        }        public GetProjectNotificationConfig build() {
            return new GetProjectNotificationConfig(topicId);
        }
    }
}
