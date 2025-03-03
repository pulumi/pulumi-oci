// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetReplicationSchedulePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetReplicationSchedulePlainArgs Empty = new GetReplicationSchedulePlainArgs();

    /**
     * Unique replication schedule identifier in path
     * 
     */
    @Import(name="replicationScheduleId", required=true)
    private String replicationScheduleId;

    /**
     * @return Unique replication schedule identifier in path
     * 
     */
    public String replicationScheduleId() {
        return this.replicationScheduleId;
    }

    private GetReplicationSchedulePlainArgs() {}

    private GetReplicationSchedulePlainArgs(GetReplicationSchedulePlainArgs $) {
        this.replicationScheduleId = $.replicationScheduleId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetReplicationSchedulePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetReplicationSchedulePlainArgs $;

        public Builder() {
            $ = new GetReplicationSchedulePlainArgs();
        }

        public Builder(GetReplicationSchedulePlainArgs defaults) {
            $ = new GetReplicationSchedulePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param replicationScheduleId Unique replication schedule identifier in path
         * 
         * @return builder
         * 
         */
        public Builder replicationScheduleId(String replicationScheduleId) {
            $.replicationScheduleId = replicationScheduleId;
            return this;
        }

        public GetReplicationSchedulePlainArgs build() {
            if ($.replicationScheduleId == null) {
                throw new MissingRequiredPropertyException("GetReplicationSchedulePlainArgs", "replicationScheduleId");
            }
            return $;
        }
    }

}
