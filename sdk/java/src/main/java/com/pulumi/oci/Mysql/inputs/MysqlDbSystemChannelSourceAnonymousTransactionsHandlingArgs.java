// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs extends com.pulumi.resources.ResourceArgs {

    public static final MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs Empty = new MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs();

    /**
     * Specifies one of the coordinates (file) at which the replica should begin reading the source&#39;s log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
     * 
     */
    @Import(name="lastConfiguredLogFilename")
    private @Nullable Output<String> lastConfiguredLogFilename;

    /**
     * @return Specifies one of the coordinates (file) at which the replica should begin reading the source&#39;s log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
     * 
     */
    public Optional<Output<String>> lastConfiguredLogFilename() {
        return Optional.ofNullable(this.lastConfiguredLogFilename);
    }

    /**
     * Specifies one of the coordinates (offset) at which the replica should begin reading the source&#39;s log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
     * 
     */
    @Import(name="lastConfiguredLogOffset")
    private @Nullable Output<String> lastConfiguredLogOffset;

    /**
     * @return Specifies one of the coordinates (offset) at which the replica should begin reading the source&#39;s log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
     * 
     */
    public Optional<Output<String>> lastConfiguredLogOffset() {
        return Optional.ofNullable(this.lastConfiguredLogOffset);
    }

    /**
     * Specifies how the replication channel handles anonymous transactions.
     * 
     */
    @Import(name="policy")
    private @Nullable Output<String> policy;

    /**
     * @return Specifies how the replication channel handles anonymous transactions.
     * 
     */
    public Optional<Output<String>> policy() {
        return Optional.ofNullable(this.policy);
    }

    /**
     * The UUID that is used as a prefix when generating transaction identifiers for anonymous transactions coming from the source. You can change the UUID later.
     * 
     */
    @Import(name="uuid")
    private @Nullable Output<String> uuid;

    /**
     * @return The UUID that is used as a prefix when generating transaction identifiers for anonymous transactions coming from the source. You can change the UUID later.
     * 
     */
    public Optional<Output<String>> uuid() {
        return Optional.ofNullable(this.uuid);
    }

    private MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs() {}

    private MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs(MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs $) {
        this.lastConfiguredLogFilename = $.lastConfiguredLogFilename;
        this.lastConfiguredLogOffset = $.lastConfiguredLogOffset;
        this.policy = $.policy;
        this.uuid = $.uuid;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs $;

        public Builder() {
            $ = new MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs();
        }

        public Builder(MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs defaults) {
            $ = new MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param lastConfiguredLogFilename Specifies one of the coordinates (file) at which the replica should begin reading the source&#39;s log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
         * 
         * @return builder
         * 
         */
        public Builder lastConfiguredLogFilename(@Nullable Output<String> lastConfiguredLogFilename) {
            $.lastConfiguredLogFilename = lastConfiguredLogFilename;
            return this;
        }

        /**
         * @param lastConfiguredLogFilename Specifies one of the coordinates (file) at which the replica should begin reading the source&#39;s log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
         * 
         * @return builder
         * 
         */
        public Builder lastConfiguredLogFilename(String lastConfiguredLogFilename) {
            return lastConfiguredLogFilename(Output.of(lastConfiguredLogFilename));
        }

        /**
         * @param lastConfiguredLogOffset Specifies one of the coordinates (offset) at which the replica should begin reading the source&#39;s log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
         * 
         * @return builder
         * 
         */
        public Builder lastConfiguredLogOffset(@Nullable Output<String> lastConfiguredLogOffset) {
            $.lastConfiguredLogOffset = lastConfiguredLogOffset;
            return this;
        }

        /**
         * @param lastConfiguredLogOffset Specifies one of the coordinates (offset) at which the replica should begin reading the source&#39;s log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
         * 
         * @return builder
         * 
         */
        public Builder lastConfiguredLogOffset(String lastConfiguredLogOffset) {
            return lastConfiguredLogOffset(Output.of(lastConfiguredLogOffset));
        }

        /**
         * @param policy Specifies how the replication channel handles anonymous transactions.
         * 
         * @return builder
         * 
         */
        public Builder policy(@Nullable Output<String> policy) {
            $.policy = policy;
            return this;
        }

        /**
         * @param policy Specifies how the replication channel handles anonymous transactions.
         * 
         * @return builder
         * 
         */
        public Builder policy(String policy) {
            return policy(Output.of(policy));
        }

        /**
         * @param uuid The UUID that is used as a prefix when generating transaction identifiers for anonymous transactions coming from the source. You can change the UUID later.
         * 
         * @return builder
         * 
         */
        public Builder uuid(@Nullable Output<String> uuid) {
            $.uuid = uuid;
            return this;
        }

        /**
         * @param uuid The UUID that is used as a prefix when generating transaction identifiers for anonymous transactions coming from the source. You can change the UUID later.
         * 
         * @return builder
         * 
         */
        public Builder uuid(String uuid) {
            return uuid(Output.of(uuid));
        }

        public MysqlDbSystemChannelSourceAnonymousTransactionsHandlingArgs build() {
            return $;
        }
    }

}