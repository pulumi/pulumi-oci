// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataLabellingService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DatasetDatasetFormatDetailsTextFileTypeMetadataArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatasetDatasetFormatDetailsTextFileTypeMetadataArgs Empty = new DatasetDatasetFormatDetailsTextFileTypeMetadataArgs();

    /**
     * A column delimiter
     * 
     */
    @Import(name="columnDelimiter")
    private @Nullable Output<String> columnDelimiter;

    /**
     * @return A column delimiter
     * 
     */
    public Optional<Output<String>> columnDelimiter() {
        return Optional.ofNullable(this.columnDelimiter);
    }

    /**
     * The index of a selected column. This is a zero-based index.
     * 
     */
    @Import(name="columnIndex", required=true)
    private Output<Integer> columnIndex;

    /**
     * @return The index of a selected column. This is a zero-based index.
     * 
     */
    public Output<Integer> columnIndex() {
        return this.columnIndex;
    }

    /**
     * The name of a selected column.
     * 
     */
    @Import(name="columnName")
    private @Nullable Output<String> columnName;

    /**
     * @return The name of a selected column.
     * 
     */
    public Optional<Output<String>> columnName() {
        return Optional.ofNullable(this.columnName);
    }

    /**
     * An escape character.
     * 
     */
    @Import(name="escapeCharacter")
    private @Nullable Output<String> escapeCharacter;

    /**
     * @return An escape character.
     * 
     */
    public Optional<Output<String>> escapeCharacter() {
        return Optional.ofNullable(this.escapeCharacter);
    }

    /**
     * It defines the format type of text files.
     * 
     */
    @Import(name="formatType", required=true)
    private Output<String> formatType;

    /**
     * @return It defines the format type of text files.
     * 
     */
    public Output<String> formatType() {
        return this.formatType;
    }

    /**
     * A line delimiter.
     * 
     */
    @Import(name="lineDelimiter")
    private @Nullable Output<String> lineDelimiter;

    /**
     * @return A line delimiter.
     * 
     */
    public Optional<Output<String>> lineDelimiter() {
        return Optional.ofNullable(this.lineDelimiter);
    }

    private DatasetDatasetFormatDetailsTextFileTypeMetadataArgs() {}

    private DatasetDatasetFormatDetailsTextFileTypeMetadataArgs(DatasetDatasetFormatDetailsTextFileTypeMetadataArgs $) {
        this.columnDelimiter = $.columnDelimiter;
        this.columnIndex = $.columnIndex;
        this.columnName = $.columnName;
        this.escapeCharacter = $.escapeCharacter;
        this.formatType = $.formatType;
        this.lineDelimiter = $.lineDelimiter;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatasetDatasetFormatDetailsTextFileTypeMetadataArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatasetDatasetFormatDetailsTextFileTypeMetadataArgs $;

        public Builder() {
            $ = new DatasetDatasetFormatDetailsTextFileTypeMetadataArgs();
        }

        public Builder(DatasetDatasetFormatDetailsTextFileTypeMetadataArgs defaults) {
            $ = new DatasetDatasetFormatDetailsTextFileTypeMetadataArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param columnDelimiter A column delimiter
         * 
         * @return builder
         * 
         */
        public Builder columnDelimiter(@Nullable Output<String> columnDelimiter) {
            $.columnDelimiter = columnDelimiter;
            return this;
        }

        /**
         * @param columnDelimiter A column delimiter
         * 
         * @return builder
         * 
         */
        public Builder columnDelimiter(String columnDelimiter) {
            return columnDelimiter(Output.of(columnDelimiter));
        }

        /**
         * @param columnIndex The index of a selected column. This is a zero-based index.
         * 
         * @return builder
         * 
         */
        public Builder columnIndex(Output<Integer> columnIndex) {
            $.columnIndex = columnIndex;
            return this;
        }

        /**
         * @param columnIndex The index of a selected column. This is a zero-based index.
         * 
         * @return builder
         * 
         */
        public Builder columnIndex(Integer columnIndex) {
            return columnIndex(Output.of(columnIndex));
        }

        /**
         * @param columnName The name of a selected column.
         * 
         * @return builder
         * 
         */
        public Builder columnName(@Nullable Output<String> columnName) {
            $.columnName = columnName;
            return this;
        }

        /**
         * @param columnName The name of a selected column.
         * 
         * @return builder
         * 
         */
        public Builder columnName(String columnName) {
            return columnName(Output.of(columnName));
        }

        /**
         * @param escapeCharacter An escape character.
         * 
         * @return builder
         * 
         */
        public Builder escapeCharacter(@Nullable Output<String> escapeCharacter) {
            $.escapeCharacter = escapeCharacter;
            return this;
        }

        /**
         * @param escapeCharacter An escape character.
         * 
         * @return builder
         * 
         */
        public Builder escapeCharacter(String escapeCharacter) {
            return escapeCharacter(Output.of(escapeCharacter));
        }

        /**
         * @param formatType It defines the format type of text files.
         * 
         * @return builder
         * 
         */
        public Builder formatType(Output<String> formatType) {
            $.formatType = formatType;
            return this;
        }

        /**
         * @param formatType It defines the format type of text files.
         * 
         * @return builder
         * 
         */
        public Builder formatType(String formatType) {
            return formatType(Output.of(formatType));
        }

        /**
         * @param lineDelimiter A line delimiter.
         * 
         * @return builder
         * 
         */
        public Builder lineDelimiter(@Nullable Output<String> lineDelimiter) {
            $.lineDelimiter = lineDelimiter;
            return this;
        }

        /**
         * @param lineDelimiter A line delimiter.
         * 
         * @return builder
         * 
         */
        public Builder lineDelimiter(String lineDelimiter) {
            return lineDelimiter(Output.of(lineDelimiter));
        }

        public DatasetDatasetFormatDetailsTextFileTypeMetadataArgs build() {
            $.columnIndex = Objects.requireNonNull($.columnIndex, "expected parameter 'columnIndex' to be non-null");
            $.formatType = Objects.requireNonNull($.formatType, "expected parameter 'formatType' to be non-null");
            return $;
        }
    }

}