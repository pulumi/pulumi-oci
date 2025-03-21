// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetTargetDatabasePeerTargetDatabaseArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTargetDatabasePeerTargetDatabaseArgs Empty = new GetTargetDatabasePeerTargetDatabaseArgs();

    /**
     * The unique id of the peer target database.
     * 
     */
    @Import(name="peerTargetDatabaseId", required=true)
    private Output<String> peerTargetDatabaseId;

    /**
     * @return The unique id of the peer target database.
     * 
     */
    public Output<String> peerTargetDatabaseId() {
        return this.peerTargetDatabaseId;
    }

    /**
     * The OCID of the Data Safe target database.
     * 
     */
    @Import(name="targetDatabaseId", required=true)
    private Output<String> targetDatabaseId;

    /**
     * @return The OCID of the Data Safe target database.
     * 
     */
    public Output<String> targetDatabaseId() {
        return this.targetDatabaseId;
    }

    private GetTargetDatabasePeerTargetDatabaseArgs() {}

    private GetTargetDatabasePeerTargetDatabaseArgs(GetTargetDatabasePeerTargetDatabaseArgs $) {
        this.peerTargetDatabaseId = $.peerTargetDatabaseId;
        this.targetDatabaseId = $.targetDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTargetDatabasePeerTargetDatabaseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTargetDatabasePeerTargetDatabaseArgs $;

        public Builder() {
            $ = new GetTargetDatabasePeerTargetDatabaseArgs();
        }

        public Builder(GetTargetDatabasePeerTargetDatabaseArgs defaults) {
            $ = new GetTargetDatabasePeerTargetDatabaseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param peerTargetDatabaseId The unique id of the peer target database.
         * 
         * @return builder
         * 
         */
        public Builder peerTargetDatabaseId(Output<String> peerTargetDatabaseId) {
            $.peerTargetDatabaseId = peerTargetDatabaseId;
            return this;
        }

        /**
         * @param peerTargetDatabaseId The unique id of the peer target database.
         * 
         * @return builder
         * 
         */
        public Builder peerTargetDatabaseId(String peerTargetDatabaseId) {
            return peerTargetDatabaseId(Output.of(peerTargetDatabaseId));
        }

        /**
         * @param targetDatabaseId The OCID of the Data Safe target database.
         * 
         * @return builder
         * 
         */
        public Builder targetDatabaseId(Output<String> targetDatabaseId) {
            $.targetDatabaseId = targetDatabaseId;
            return this;
        }

        /**
         * @param targetDatabaseId The OCID of the Data Safe target database.
         * 
         * @return builder
         * 
         */
        public Builder targetDatabaseId(String targetDatabaseId) {
            return targetDatabaseId(Output.of(targetDatabaseId));
        }

        public GetTargetDatabasePeerTargetDatabaseArgs build() {
            if ($.peerTargetDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetTargetDatabasePeerTargetDatabaseArgs", "peerTargetDatabaseId");
            }
            if ($.targetDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetTargetDatabasePeerTargetDatabaseArgs", "targetDatabaseId");
            }
            return $;
        }
    }

}
