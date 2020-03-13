namespace DllValidator
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.button1 = new System.Windows.Forms.Button();
            this.result = new System.Windows.Forms.RichTextBox();
            this.OnlyErrorsAndWarnings = new System.Windows.Forms.CheckBox();
            this.PrintImport = new System.Windows.Forms.CheckBox();
            this.AllDirectoriesFiles = new System.Windows.Forms.CheckBox();
            this.PrintExport = new System.Windows.Forms.CheckBox();
            this.button2 = new System.Windows.Forms.Button();
            this.progressBar1 = new System.Windows.Forms.ProgressBar();
            this.onlyPE = new System.Windows.Forms.CheckBox();
            this.SuspendLayout();
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            this.openFileDialog1.Filter = resources.GetString("openFileDialog1.Filter");
            this.openFileDialog1.Multiselect = true;
            this.openFileDialog1.RestoreDirectory = true;
            this.openFileDialog1.SupportMultiDottedExtensions = true;
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(12, 12);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(75, 23);
            this.button1.TabIndex = 0;
            this.button1.Text = "Check";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // result
            // 
            this.result.Font = new System.Drawing.Font("Courier New", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.result.Location = new System.Drawing.Point(2, 41);
            this.result.Name = "result";
            this.result.ReadOnly = true;
            this.result.Size = new System.Drawing.Size(1257, 660);
            this.result.TabIndex = 1;
            this.result.Text = "";
            // 
            // OnlyErrorsAndWarnings
            // 
            this.OnlyErrorsAndWarnings.AutoSize = true;
            this.OnlyErrorsAndWarnings.Location = new System.Drawing.Point(93, 2);
            this.OnlyErrorsAndWarnings.Name = "OnlyErrorsAndWarnings";
            this.OnlyErrorsAndWarnings.Size = new System.Drawing.Size(142, 17);
            this.OnlyErrorsAndWarnings.TabIndex = 2;
            this.OnlyErrorsAndWarnings.Text = "Only errors and warnings";
            this.OnlyErrorsAndWarnings.UseVisualStyleBackColor = true;
            // 
            // PrintImport
            // 
            this.PrintImport.AutoSize = true;
            this.PrintImport.Location = new System.Drawing.Point(93, 18);
            this.PrintImport.Name = "PrintImport";
            this.PrintImport.Size = new System.Drawing.Size(109, 17);
            this.PrintImport.TabIndex = 3;
            this.PrintImport.Text = "Print import tables";
            this.PrintImport.UseVisualStyleBackColor = true;
            // 
            // AllDirectoriesFiles
            // 
            this.AllDirectoriesFiles.AutoSize = true;
            this.AllDirectoriesFiles.Location = new System.Drawing.Point(241, 2);
            this.AllDirectoriesFiles.Name = "AllDirectoriesFiles";
            this.AllDirectoriesFiles.Size = new System.Drawing.Size(201, 17);
            this.AllDirectoriesFiles.TabIndex = 4;
            this.AllDirectoriesFiles.Text = "All files in directory and subdirectories";
            this.AllDirectoriesFiles.UseVisualStyleBackColor = true;
            // 
            // PrintExport
            // 
            this.PrintExport.AutoSize = true;
            this.PrintExport.Location = new System.Drawing.Point(241, 18);
            this.PrintExport.Name = "PrintExport";
            this.PrintExport.Size = new System.Drawing.Size(110, 17);
            this.PrintExport.TabIndex = 5;
            this.PrintExport.Text = "Print export tables";
            this.PrintExport.UseVisualStyleBackColor = true;
            // 
            // button2
            // 
            this.button2.Enabled = false;
            this.button2.Font = new System.Drawing.Font("Microsoft Sans Serif", 8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.button2.Location = new System.Drawing.Point(468, 18);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(75, 19);
            this.button2.TabIndex = 6;
            this.button2.Text = "Stop";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.button2_Click);
            // 
            // progressBar1
            // 
            this.progressBar1.Location = new System.Drawing.Point(468, 2);
            this.progressBar1.Name = "progressBar1";
            this.progressBar1.Size = new System.Drawing.Size(100, 17);
            this.progressBar1.Step = 1;
            this.progressBar1.TabIndex = 7;
            // 
            // onlyPE
            // 
            this.onlyPE.AutoSize = true;
            this.onlyPE.Location = new System.Drawing.Point(573, 20);
            this.onlyPE.Name = "onlyPE";
            this.onlyPE.Size = new System.Drawing.Size(153, 17);
            this.onlyPE.TabIndex = 8;
            this.onlyPE.Text = "Use PE-files extension filter";
            this.onlyPE.UseVisualStyleBackColor = true;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1261, 703);
            this.Controls.Add(this.onlyPE);
            this.Controls.Add(this.progressBar1);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.PrintExport);
            this.Controls.Add(this.AllDirectoriesFiles);
            this.Controls.Add(this.PrintImport);
            this.Controls.Add(this.OnlyErrorsAndWarnings);
            this.Controls.Add(this.result);
            this.Controls.Add(this.button1);
            this.Name = "Form1";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.RichTextBox result;
        private System.Windows.Forms.CheckBox OnlyErrorsAndWarnings;
        private System.Windows.Forms.CheckBox PrintImport;
        private System.Windows.Forms.CheckBox AllDirectoriesFiles;
        private System.Windows.Forms.CheckBox PrintExport;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.ProgressBar progressBar1;
        private System.Windows.Forms.CheckBox onlyPE;
    }
}

