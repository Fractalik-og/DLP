namespace DLP.UsbController
{
    partial class MainForm
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
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
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            SuspendLayout();

            // Свойства формы (параметризованы, чтобы не конфликтовать с типом AutoScaleMode).
            this.AutoScaleMode = AutoScaleMode.Font;
            this.ClientSize = new Size(1000, 640);
            this.Text = "DLP USB Analyzer";
            this.StartPosition = FormStartPosition.CenterScreen;

            // Порядок добавления важен для Dock: Fill добавляется раньше, чем Top/Bottom.
            this.Controls.Add(_grid);       // Dock.Fill
            this.Controls.Add(_toolStrip);  // Dock.Top
            this.Controls.Add(_statusStrip);// Dock.Bottom

            ResumeLayout(false);
            PerformLayout();
        }

        #endregion
    }
}
