// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MysqlDbSystemChannelTargetFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final MysqlDbSystemChannelTargetFilterArgs Empty = new MysqlDbSystemChannelTargetFilterArgs();

    /**
     * The type of the filter rule.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return The type of the filter rule.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    /**
     * The body of the filter rule. This can represent a database, a table, or a database pair (represented as &#34;db1-&gt;db2&#34;). For more information, see [Replication Filtering Rules](https://dev.mysql.com/doc/refman/8.0/en/replication-rules.html).
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return The body of the filter rule. This can represent a database, a table, or a database pair (represented as &#34;db1-&gt;db2&#34;). For more information, see [Replication Filtering Rules](https://dev.mysql.com/doc/refman/8.0/en/replication-rules.html).
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private MysqlDbSystemChannelTargetFilterArgs() {}

    private MysqlDbSystemChannelTargetFilterArgs(MysqlDbSystemChannelTargetFilterArgs $) {
        this.type = $.type;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MysqlDbSystemChannelTargetFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MysqlDbSystemChannelTargetFilterArgs $;

        public Builder() {
            $ = new MysqlDbSystemChannelTargetFilterArgs();
        }

        public Builder(MysqlDbSystemChannelTargetFilterArgs defaults) {
            $ = new MysqlDbSystemChannelTargetFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param type The type of the filter rule.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type The type of the filter rule.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param value The body of the filter rule. This can represent a database, a table, or a database pair (represented as &#34;db1-&gt;db2&#34;). For more information, see [Replication Filtering Rules](https://dev.mysql.com/doc/refman/8.0/en/replication-rules.html).
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value The body of the filter rule. This can represent a database, a table, or a database pair (represented as &#34;db1-&gt;db2&#34;). For more information, see [Replication Filtering Rules](https://dev.mysql.com/doc/refman/8.0/en/replication-rules.html).
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public MysqlDbSystemChannelTargetFilterArgs build() {
            return $;
        }
    }

}
